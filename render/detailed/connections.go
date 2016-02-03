package detailed

import (
	"sort"

	"github.com/weaveworks/scope/render"
	"github.com/weaveworks/scope/report"
)

// Connection is the rendering of a node's connections aggregated on either a
// local or remote port.
type Connection struct {
	ID         string `json:"id"`    // Linkable node-id in the current topology
	Label      string `json:"label"` // Human-readable text of the remote node
	LocalPort  string `json:"local_port,omitempty"`
	RemotePort string `json:"remote_port,omitempty"`
	Count      int    `json:"count"`
}

// connections renders the connections of this report.Node, aggregating and
// counting them by local/remote port as appropriate.
func connections(r report.Report, n render.RenderableNode) map[string][]Connection {
	incoming, outgoing := []Connection{}, []Connection{}
	return map[string][]Connection{
		"incoming": incoming,
		"outgoing": outgoing,
	}
}

/*

   // RenderableNode may be the result of merge operation(s), and so may have
   // multiple origins. The ultimate goal here is to generate tables to view
   // in the UI, so we skip the intermediate representations, but we could
   // add them later.
   connections := []Row{}
   for _, id := range n.Origins {
           if table, ok := OriginTable(r, id, multiHost, multiContainer); ok {
                   tables = append(tables, table)
           } else if _, ok := r.Endpoint.Nodes[id]; ok {
                   connections = append(connections, connectionDetailsRows(r.Endpoint, id)...)
           } else if _, ok := r.Address.Nodes[id]; ok {
                   connections = append(connections, connectionDetailsRows(r.Address, id)...)
           }
   }

func connectionsTable(connections []Row, r report.Report, n RenderableNode) (Table, bool) {
	sec := r.Window.Seconds()
	rate := func(u *uint64) (float64, bool) {
		if u == nil {
			return 0.0, false
		}
		if sec <= 0 {
			return 0.0, true
		}
		return float64(*u) / sec, true
	}
	shortenByteRate := func(rate float64) (major, minor string) {
		switch {
		case rate > 1024*1024:
			return fmt.Sprintf("%.2f", rate/1024/1024), "MBps"
		case rate > 1024:
			return fmt.Sprintf("%.1f", rate/1024), "KBps"
		default:
			return fmt.Sprintf("%.0f", rate), "Bps"
		}
	}

	rows := []Row{}
	if n.EdgeMetadata.MaxConnCountTCP != nil {
		rows = append(rows, Row{Key: "TCP connections", ValueMajor: strconv.FormatUint(*n.EdgeMetadata.MaxConnCountTCP, 10)})
	}
	if rate, ok := rate(n.EdgeMetadata.EgressPacketCount); ok {
		rows = append(rows, Row{Key: "Egress packet rate", ValueMajor: fmt.Sprintf("%.0f", rate), ValueMinor: "packets/sec"})
	}
	if rate, ok := rate(n.EdgeMetadata.IngressPacketCount); ok {
		rows = append(rows, Row{Key: "Ingress packet rate", ValueMajor: fmt.Sprintf("%.0f", rate), ValueMinor: "packets/sec"})
	}
	if rate, ok := rate(n.EdgeMetadata.EgressByteCount); ok {
		s, unit := shortenByteRate(rate)
		rows = append(rows, Row{Key: "Egress byte rate", ValueMajor: s, ValueMinor: unit})
	}
	if rate, ok := rate(n.EdgeMetadata.IngressByteCount); ok {
		s, unit := shortenByteRate(rate)
		rows = append(rows, Row{Key: "Ingress byte rate", ValueMajor: s, ValueMinor: unit})
	}
	if len(connections) > 0 {
		rows = append(rows, Row{Key: "Client", ValueMajor: "Server", Expandable: true})
		rows = append(rows, connections...)
	}
	if len(rows) > 0 {
		return Table{
			Title:   "Connections",
			Numeric: false,
			Rank:    connectionsRank,
			Rows:    rows,
		}, true
	}
	return Table{}, false
}
*/
