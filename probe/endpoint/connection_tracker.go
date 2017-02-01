package endpoint

import (
	"errors"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/weaveworks/scope/probe/endpoint/procspy"
	"github.com/weaveworks/scope/probe/process"
	"github.com/weaveworks/scope/report"
)

// TODO: there is better way to do it, like using an interface
// connectionTrackerConfig are the config options for the endpoint tracker.
type connectionTrackerConfig struct {
	HostID       string
	HostName     string
	SpyProcs     bool
	UseConntrack bool
	WalkProc     bool
	UseEbpfConn  bool
	ProcRoot     string
	BufferSize   int
	Scanner      procspy.ConnectionScanner
	DNSSnooper   *DNSSnooper
}

type connectionTracker struct {
	conf            connectionTrackerConfig
	flowWalker      flowWalker // Interface
	ebpfTracker     eventTracker
	reverseResolver *reverseResolver
}

func newConnectionTracker(conf connectionTrackerConfig) connectionTracker {
	if conf.UseEbpfConn {
		// When ebpf will be active by default, check if it starts correctly otherwise fallback to flowWalk
		et, err := newEbpfTracker(conf.UseEbpfConn)
		if err != nil {
			// TODO: fallback to flowWalker, when ebpf is enabled by default
			log.Errorf("Error setting up the ebpfTracker, connections will not be reported: %s", err)
			noopConnectionTracker := connectionTracker{
				conf:            conf,
				flowWalker:      nil,
				ebpfTracker:     nil,
				reverseResolver: nil,
			}
			return noopConnectionTracker
		}
		// do a single run of conntrack and proc parsing and feed to ebpf the data.
		// we can use scanner = procspy.NewSyncConnectionScanner(processCache)
		// or we need to write our conntrack and proc parser
		fw := newConntrackFlowWalker(conf.UseConntrack, conf.ProcRoot, conf.BufferSize)
		seenTuples := map[string]fourTuple{}
		// Consult the flowWalker to get the initial state
		fw.walkFlows(func(f flow, active bool) {
			tuple := fourTuple{
				f.Original.Layer3.SrcIP,
				f.Original.Layer3.DstIP,
				uint16(f.Original.Layer4.SrcPort),
				uint16(f.Original.Layer4.DstPort),
				active,
			}
			// Handle DNAT-ed connections in the initial states.
			if f.Original.Layer3.DstIP != f.Reply.Layer3.SrcIP {
				tuple = fourTuple{
					f.Reply.Layer3.DstIP,
					f.Reply.Layer3.SrcIP,
					uint16(f.Reply.Layer4.DstPort),
					uint16(f.Reply.Layer4.SrcPort),
					active,
				}
			}

			seenTuples[tuple.key()] = tuple
		})
		fw.stop()

		var processCache *process.CachingWalker
		var scanner procspy.ConnectionScanner
		processCache = process.NewCachingWalker(process.NewWalker(conf.ProcRoot))
		processCache.Tick()
		scanner = procspy.NewSyncConnectionScanner(processCache)
		conns, err := scanner.Connections(conf.SpyProcs)
		if err != nil {
			log.Errorf("Error initializing ebpfTracker while scanning /proc, continue without initial connections: %s", err)
			et.initializeBlank()
		} else {
			et.initialize(conns, seenTuples, report.MakeHostNodeID(conf.HostID))
		}
		ct := connectionTracker{
			conf:            conf,
			flowWalker:      nil,
			ebpfTracker:     et,
			reverseResolver: newReverseResolver(),
		}
		scanner.Stop()
		et.run()
		return ct
	}
	// ebpf OFF, use flowWalker
	return connectionTracker{
		conf:            conf,
		flowWalker:      newConntrackFlowWalker(conf.UseConntrack, conf.ProcRoot, conf.BufferSize),
		ebpfTracker:     nil,
		reverseResolver: newReverseResolver(),
	}
}

// ReportConnections calls trackers accordingly to the configuration.
// Note that performFlowWalk and performWalkProc may be invoked both, while performEbpfTracker is called only itself
func (t *connectionTracker) ReportConnections(rpt *report.Report) {
	hostNodeID := report.MakeHostNodeID(t.conf.HostID)

	if t.ebpfTracker != nil {
		t.performEbpfTracker(rpt, hostNodeID)
		return
	}

	// seeTuples contains information about connections seen by conntrack and it will be passe to the /proc parser
	seenTuples := map[string]fourTuple{}
	if t.flowWalker != nil {
		t.performFlowWalk(rpt, &seenTuples)
	}
	if t.conf.WalkProc {
		t.performWalkProc(rpt, hostNodeID, &seenTuples)
	}
}

func (t *connectionTracker) performFlowWalk(rpt *report.Report, seenTuples *map[string]fourTuple) {
	// Consult the flowWalker for short-lived connections
	extraNodeInfo := map[string]string{
		Conntracked: "true",
	}
	t.flowWalker.walkFlows(func(f flow, alive bool) {
		tuple := fourTuple{
			f.Original.Layer3.SrcIP,
			f.Original.Layer3.DstIP,
			uint16(f.Original.Layer4.SrcPort),
			uint16(f.Original.Layer4.DstPort),
			alive,
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
				alive,
			}
		}

		(*seenTuples)[tuple.key()] = tuple
		t.addConnection(rpt, tuple, "", extraNodeInfo, extraNodeInfo)
	})
}

func (t *connectionTracker) performWalkProc(rpt *report.Report, hostNodeID string, seenTuples *map[string]fourTuple) error {
	conns, err := t.conf.Scanner.Connections(t.conf.SpyProcs)
	if err != nil {
		return err
	}
	for conn := conns.Next(); conn != nil; conn = conns.Next() {
		var (
			namespaceID string
			tuple       = fourTuple{
				conn.LocalAddress.String(),
				conn.RemoteAddress.String(),
				conn.LocalPort,
				conn.RemotePort,
				true,
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
		canonical, ok := (*seenTuples)[tuple.key()]
		if (ok && canonical != tuple) || (!ok && tuple.fromPort < tuple.toPort) {
			tuple.reverse()
			toNodeInfo, fromNodeInfo = fromNodeInfo, toNodeInfo
		}
		t.addConnection(rpt, tuple, namespaceID, fromNodeInfo, toNodeInfo)
	}
	return nil
}

func (t *connectionTracker) performEbpfTracker(rpt *report.Report, hostNodeID string) error {
	// ebpf flow, just run ebpf, initialization needs to be done somewhere else.
	if !t.ebpfTracker.hasDied() {
		t.ebpfTracker.walkConnections(func(e ebpfConnection) {
			fromNodeInfo := map[string]string{
				Procspied: "true",
				EBPF:      "true",
			}
			toNodeInfo := map[string]string{
				Procspied: "true",
				EBPF:      "true",
			}
			if e.pid > 0 {
				fromNodeInfo[process.PID] = strconv.Itoa(e.pid)
				fromNodeInfo[report.HostNodeID] = hostNodeID
			}

			if e.incoming {
				t.addConnection(rpt, reverse(e.tuple), e.networkNamespace, toNodeInfo, fromNodeInfo)
			} else {
				t.addConnection(rpt, e.tuple, e.networkNamespace, fromNodeInfo, toNodeInfo)
			}

		})
		return nil
	}
	return errors.New("ebpfTracker died")
}

func (t *connectionTracker) addConnection(rpt *report.Report, ft fourTuple, namespaceID string, extraFromNode, extraToNode map[string]string) {
	var (
		fromNode = t.makeEndpointNode(namespaceID, ft.fromAddr, ft.fromPort, extraFromNode)
		toNode   = t.makeEndpointNode(namespaceID, ft.toAddr, ft.toPort, extraToNode)
	)
	rpt.Endpoint = rpt.Endpoint.AddNode(fromNode.WithEdge(toNode.ID, report.EdgeMetadata{}))
	rpt.Endpoint = rpt.Endpoint.AddNode(toNode)
}

func (t *connectionTracker) makeEndpointNode(namespaceID string, addr string, port uint16, extra map[string]string) report.Node {
	portStr := strconv.Itoa(int(port))
	node := report.MakeNodeWith(
		report.MakeEndpointNodeID(t.conf.HostID, namespaceID, addr, portStr),
		map[string]string{Addr: addr, Port: portStr})
	if names := t.conf.DNSSnooper.CachedNamesForIP(addr); len(names) > 0 {
		node = node.WithSet(SnoopedDNSNames, report.MakeStringSet(names...))
	}
	if names, err := t.reverseResolver.get(addr); err == nil && len(names) > 0 {
		node = node.WithSet(ReverseDNSNames, report.MakeStringSet(names...))
	}
	if extra != nil {
		node = node.WithLatests(extra)
	}
	return node
}

func (t *connectionTracker) Stop() error {
	if t.ebpfTracker != nil {
		t.ebpfTracker.stop()
	}
	if t.flowWalker != nil {
		t.flowWalker.stop()
	}
	t.reverseResolver.stop()
	return nil
}
