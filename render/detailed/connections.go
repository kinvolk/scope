package detailed

import (
	"strconv"
	"strings"

	"github.com/weaveworks/scope/render"
	"github.com/weaveworks/scope/report"
)

const (
	remotePortKey = "remote_port"
	localPortKey  = "local_port"
	countKey      = "count"
	number        = "number"
)

func makeIncomingConnectionsTable(n render.RenderableNode, ns render.RenderableNodes) NodeSummaryGroup {
	// Get all endpoint ids which are children of this node
	myEndpoints := report.MakeIDList()
	n.Children.ForEach(func(child render.RenderableNode) {
		if child.Topology == report.Endpoint {
			myEndpoints = append(myEndpoints, child.ID)
		}
	})

	// Get the endpoint children of all nodes which point to one of my endpoint children
	endpoints := map[string][]render.RenderableNode{}
	for _, node := range ns {
		if !node.Adjacency.Contains(n.ID) {
			continue
		}

		node.Children.ForEach(func(child render.RenderableNode) {
			if child.Topology != report.Endpoint {
				return
			}

			for _, endpoint := range child.Adjacency.Intersection(myEndpoints) {
				endpoints[endpoint] = append(endpoints[endpoint], child)
			}
		})
	}

	// Dedupe nodes talking to same port multiple times
	remotes := map[string]int{}
	for myend, nodes := range endpoints {
		// what port are they talking to?
		parts := strings.SplitN(myend, ":", 4)
		if len(parts) != 4 {
			continue
		}
		port := parts[3]

		for _, node := range nodes {
			// what is their IP address?
			if parts := strings.SplitN(node.ID, ":", 4); len(parts) == 4 {
				key := parts[2] + "|" + port
				remotes[key] = remotes[key] + 1
			}
		}
	}

	return NodeSummaryGroup{
		ID:    "incoming-connections",
		Label: "Inbound",
		Columns: []Column{
			{ID: localPortKey, Label: "Port"},
			{ID: countKey, Label: "Count", DefaultSort: true},
		},
		Nodes: buildConnectionNodes(remotes, localPortKey),
	}
}

func makeOutgoingConnectionsTable(n render.RenderableNode, ns render.RenderableNodes) NodeSummaryGroup {
	// Get all endpoints which are children of this node
	endpoints := []render.RenderableNode{}
	n.Children.ForEach(func(child render.RenderableNode) {
		if child.Topology == report.Endpoint {
			endpoints = append(endpoints, child)
		}
	})

	// Dedupe children talking to same port multiple times
	remotes := map[string]int{}
	for _, node := range endpoints {
		for _, adjacent := range node.Adjacency {
			if parts := strings.SplitN(adjacent, ":", 4); len(parts) == 4 {
				key := parts[2] + "|" + parts[3]
				remotes[key] = remotes[key] + 1
			}
		}
	}

	return NodeSummaryGroup{
		ID:    "outgoing-connections",
		Label: "Outbound",
		Columns: []Column{
			{ID: remotePortKey, Label: "Port"},
			{ID: countKey, Label: "Count", DefaultSort: true},
		},
		Nodes: buildConnectionNodes(remotes, remotePortKey),
	}
}

func buildConnectionNodes(in map[string]int, columnKey string) []NodeSummary {
	nodes := []NodeSummary{}
	for key, count := range in {
		parts := strings.SplitN(key, "|", 2)
		nodes = append(nodes, NodeSummary{
			ID:    key,
			Label: parts[0],
			Metadata: []MetadataRow{
				{
					ID:       columnKey,
					Value:    parts[1],
					Datatype: number,
				},
				{
					ID:       countKey,
					Value:    strconv.Itoa(count),
					Datatype: number,
				},
			},
		})
	}
	return nodes
}
