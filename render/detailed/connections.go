package detailed

import (
	"net"

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
	Count      uint64 `json:"count"`
}

// Connections renders the connections of this report.Node, aggregating and
// counting them by local/remote port as appropriate.
func Connections(r report.Report, n render.RenderableNode) map[string][]Connection {
	// For each endpoint/address in n.Children (or possibly by n.Node.Edges)
	incoming, outgoing := []Connection{}, []Connection{}
	n.Node.Edges.ForEach(func(dst string, edge report.EdgeMetadata) {
		// find the node containing that endpoint in current topology
		// count connections to that node by local/remote port
		// TODO: dst looks like
		// Edge "host:vagrant-ubuntu-vivid-64" Destination: ";172.16.0.3"
		// Edge "host:vagrant-ubuntu-vivid-64" Destination: "vagrant-ubuntu-vivid-64;127.0.0.1"
		// Edge "host:vagrant-ubuntu-vivid-64" Destination: ";10.0.2.15"
		// Edge "host:vagrant-ubuntu-vivid-64" Destination: "vagrant-ubuntu-vivid-64;127.0.0.1;4040"
		// Edge "host:vagrant-ubuntu-vivid-64" Destination: "vagrant-ubuntu-vivid-64;127.0.0.1;6784"
		// Edge "host:vagrant-ubuntu-vivid-64" Destination: ";10.32.0.2;80"
		// Edge "host:vagrant-ubuntu-vivid-64" Destination: ";172.16.0.3"
		// Edge "host:vagrant-ubuntu-vivid-64" Destination: "vagrant-ubuntu-vivid-64;127.0.0.1"
		// Edge "host:vagrant-ubuntu-vivid-64" Destination: ";10.0.2.15"
		// Edge "host:vagrant-ubuntu-vivid-64" Destination: "vagrant-ubuntu-vivid-64;127.0.0.1;4040"
		// Edge "host:vagrant-ubuntu-vivid-64" Destination: "vagrant-ubuntu-vivid-64;127.0.0.1;6784"
		// Edge "host:vagrant-ubuntu-vivid-64" Destination: ";10.32.0.2;80"
		host, port, err := net.SplitHostPort(dst)
		if err != nil {
			return
		}
		var count uint64
		if edge.MaxConnCountTCP != nil {
			count = *edge.MaxConnCountTCP
		}
		incoming = append(incoming, Connection{ID: dst, Label: host, RemotePort: port, Count: count})
	})
	var result map[string][]Connection
	if len(incoming) > 0 {
		if result == nil {
			result = map[string][]Connection{}
		}
		result["incoming"] = incoming
	}
	if len(outgoing) > 0 {
		if result == nil {
			result = map[string][]Connection{}
		}
		result["outgoing"] = outgoing
	}
	return result
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

func connectionDetailsRows(topology report.Topology, originID string) []Row {
       rows := []Row{}
       labeler := func(nodeID string, sets report.Sets) (string, bool) {
               if _, addr, port, ok := report.ParseEndpointNodeID(nodeID); ok {
                       if names, ok := sets["name"]; ok {
                               return fmt.Sprintf("%s:%s", names[0], port), true
                       }
                       return fmt.Sprintf("%s:%s", addr, port), true
               }
               if _, addr, ok := report.ParseAddressNodeID(nodeID); ok {
                       return addr, true
               }
               return "", false
       }
       local, ok := labeler(originID, topology.Nodes[originID].Sets)
       if !ok {
               return rows
       }
       // Firstly, collection outgoing connections from this node.
       for _, serverNodeID := range topology.Nodes[originID].Adjacency {
               remote, ok := labeler(serverNodeID, topology.Nodes[serverNodeID].Sets)
               if !ok {
                       continue
               }
               rows = append(rows, Row{
                       Key:        local,
                       ValueMajor: remote,
                       Expandable: true,
               })
       }
       // Next, scan the topology for incoming connections to this node.
       for clientNodeID, clientNode := range topology.Nodes {
               if clientNodeID == originID {
                       continue
               }
               serverNodeIDs := clientNode.Adjacency
               if !serverNodeIDs.Contains(originID) {
                       continue
               }
               remote, ok := labeler(clientNodeID, clientNode.Sets)
               if !ok {
                       continue
               }
               rows = append(rows, Row{
                       Key:        remote,
                       ValueMajor: local,
                       ValueMinor: "",
                       Expandable: true,
               })
       }
       return rows
}
*/
