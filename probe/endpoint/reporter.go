package endpoint

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/weaveworks/scope/probe/endpoint/procspy"
	"github.com/weaveworks/scope/probe/process"
	"github.com/weaveworks/scope/report"
)

// Node metadata keys.
const (
	Addr            = "addr" // typically IPv4
	Port            = "port"
	Conntracked     = "conntracked"
	EBPF            = "eBPF"
	Procspied       = "procspied"
	ReverseDNSNames = "reverse_dns_names"
)

// Reporter generates Reports containing the Endpoint topology.
type Reporter struct {
	hostID          string
	hostName        string
	spyProcs        bool
	walkProc        bool
	ebpfEnabled     bool
	flowWalker      flowWalker // interface
	ebpfTracker     eventTracker
	scanner         procspy.ConnectionScanner
	natMapper       natMapper
	reverseResolver *reverseResolver
}

// SpyDuration is an exported prometheus metric
var SpyDuration = prometheus.NewSummaryVec(
	prometheus.SummaryOpts{
		Namespace: "scope",
		Subsystem: "probe",
		Name:      "spy_duration_seconds",
		Help:      "Time in seconds spent spying on active connections.",
		MaxAge:    10 * time.Second, // like statsd
	},
	[]string{},
)

// NewReporter creates a new Reporter that invokes procspy.Connections to
// generate a report.Report that contains every discovered (spied) connection
// on the host machine, at the granularity of host and port. That information
// is stored in the Endpoint topology. It optionally enriches that topology
// with process (PID) information.
func NewReporter(hostID, hostName string, spyProcs, useConntrack, walkProc, ebpfEnabled bool, procRoot string, scanner procspy.ConnectionScanner) *Reporter {
	return &Reporter{
		hostID:          hostID,
		hostName:        hostName,
		spyProcs:        spyProcs,
		walkProc:        walkProc,
		ebpfEnabled:     ebpfEnabled,
		flowWalker:      newConntrackFlowWalker(useConntrack, procRoot),
		ebpfTracker:     newEbpfTracker(ebpfEnabled),
		natMapper:       makeNATMapper(newConntrackFlowWalker(useConntrack, procRoot, "--any-nat")),
		reverseResolver: newReverseResolver(),
		scanner:         scanner,
	}
}

// Name of this reporter, for metrics gathering
func (Reporter) Name() string { return "Endpoint" }

// Stop stop stop
func (r *Reporter) Stop() {
	r.flowWalker.stop()
	r.natMapper.stop()
	r.reverseResolver.stop()
	r.scanner.Stop()
}

// Report implements Reporter.
func (r *Reporter) Report() (report.Report, error) {
	defer func(begin time.Time) {
		SpyDuration.WithLabelValues().Observe(time.Since(begin).Seconds())
	}(time.Now())

	hostNodeID := report.MakeHostNodeID(r.hostID)
	rpt := report.MakeReport()

	seenTuples := map[string]fourTuple{}

	// Consult the flowWalker for short-lived connections
	{
		extraNodeInfo := map[string]string{
			Conntracked: "true",
		}
		r.flowWalker.walkFlows(func(f flow) {
			tuple := fourTuple{
				f.Original.Layer3.SrcIP,
				f.Original.Layer3.DstIP,
				uint16(f.Original.Layer4.SrcPort),
				uint16(f.Original.Layer4.DstPort),
			}
			// Handle DNAT-ed short-lived connections.
			// The NAT mapper won't help since it only runs periodically,
			// missing the short-lived connections.
			if f.Original.Layer3.DstIP != f.Reply.Layer3.SrcIP {
				tuple = fourTuple{
					f.Reply.Layer3.DstIP,
					f.Reply.Layer3.SrcIP,
					uint16(f.Reply.Layer4.DstPort),
					uint16(f.Reply.Layer4.SrcPort),
				}
			}

			seenTuples[tuple.key()] = tuple
			r.addConnection(&rpt, tuple, "", extraNodeInfo, extraNodeInfo)
		})
	}

	if r.walkProc {
		defer r.procParsingSwitcher()
		conns, err := r.scanner.Connections(r.spyProcs)
		if err != nil {
			return rpt, err
		}
		for conn := conns.Next(); conn != nil; conn = conns.Next() {
			var (
				namespaceID string
				tuple       = fourTuple{
					conn.LocalAddress.String(),
					conn.RemoteAddress.String(),
					conn.LocalPort,
					conn.RemotePort,
				}
				toNodeInfo   = map[string]string{Procspied: "true"}
				fromNodeInfo = map[string]string{Procspied: "true"}
			)
			if conn.Proc.PID > 0 {
				fromNodeInfo[process.PID] = strconv.FormatUint(uint64(conn.Proc.PID), 10)
				fromNodeInfo[report.HostNodeID] = hostNodeID
			}

			if conn.Proc.NetNamespaceID > 0 {
				namespaceID = strconv.FormatUint(conn.Proc.NetNamespaceID, 10)
			}

			// If we've already seen this connection, we should know the direction
			// (or have already figured it out), so we normalize and use the
			// canonical direction. Otherwise, we can use a port-heuristic to guess
			// the direction.
			canonical, ok := seenTuples[tuple.key()]
			if (ok && canonical != tuple) || (!ok && tuple.fromPort < tuple.toPort) {
				r.feedToEbpf(tuple, true, int(conn.Proc.PID), namespaceID)
				r.addConnection(&rpt, reverse(tuple), namespaceID, toNodeInfo, fromNodeInfo)
			} else {
				r.feedToEbpf(tuple, false, int(conn.Proc.PID), namespaceID)
				r.addConnection(&rpt, tuple, namespaceID, fromNodeInfo, toNodeInfo)
			}

		}
	}

	// eBPF
	if r.ebpfEnabled && !r.ebpfTracker.hasDied() {
		r.ebpfTracker.walkFlows(func(e ebpfConnection) {
			fromNodeInfo := map[string]string{
				Procspied:         "true",
				EBPF:              "true",
				process.PID:       strconv.Itoa(e.pid),
				report.HostNodeID: hostNodeID,
			}
			toNodeInfo := map[string]string{
				Procspied: "true",
				EBPF:      "true",
			}

			if e.incoming {
				r.addConnection(&rpt, reverse(e.tuple), e.networkNamespace, toNodeInfo, fromNodeInfo)
			} else {
				r.addConnection(&rpt, e.tuple, e.networkNamespace, fromNodeInfo, toNodeInfo)
			}

		})
	}

	r.natMapper.applyNAT(rpt, r.hostID)
	return rpt, nil
}

func (r *Reporter) addConnection(rpt *report.Report, t fourTuple, namespaceID string, extraFromNode, extraToNode map[string]string) {
	var (
		fromNode = r.makeEndpointNode(namespaceID, t.fromAddr, t.fromPort, extraFromNode)
		toNode   = r.makeEndpointNode(namespaceID, t.toAddr, t.toPort, extraToNode)
	)
	rpt.Endpoint = rpt.Endpoint.AddNode(fromNode.WithEdge(toNode.ID, report.EdgeMetadata{}))
	rpt.Endpoint = rpt.Endpoint.AddNode(toNode)
}

func (r *Reporter) makeEndpointNode(namespaceID string, addr string, port uint16, extra map[string]string) report.Node {
	portStr := strconv.Itoa(int(port))
	node := report.MakeNodeWith(
		report.MakeEndpointNodeID(r.hostID, namespaceID, addr, portStr),
		map[string]string{Addr: addr, Port: portStr})
	// In case we have a reverse resolution for the IP, we can use it for
	// the name...
	if names, err := r.reverseResolver.get(addr); err == nil {
		node = node.WithSet(ReverseDNSNames, report.MakeStringSet(names...))
	}
	if extra != nil {
		node = node.WithLatests(extra)
	}
	return node
}

func newu64(i uint64) *uint64 {
	return &i
}

// procParsingSwitcher make sure that if eBPF tracking is enabled,
// connections coming from /proc parsing are only walked once.
func (r *Reporter) procParsingSwitcher() {
	if r.walkProc && r.ebpfEnabled {
		r.walkProc = false
		r.ebpfTracker.initialize()
	}
}

// if the eBPF tracker is enabled, feed the existing connections into it
// incoming connections correspond to "accept" events
// outgoing connections correspond to "connect" events
func (r Reporter) feedToEbpf(tuple fourTuple, incoming bool, pid int, namespaceID string) {
	if r.ebpfEnabled && !r.ebpfTracker.isInitialized() {
		tcpEventType := "connect"

		if incoming {
			tcpEventType = "accept"
		}

		r.ebpfTracker.handleFlow(tcpEventType, tuple, pid, namespaceID)
	}
}
