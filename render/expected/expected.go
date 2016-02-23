package expected

import (
	"fmt"
	"net"

	"github.com/weaveworks/scope/render"
	"github.com/weaveworks/scope/report"
	"github.com/weaveworks/scope/test/fixture"
)

// Exported for testing.
var (
	circle   = "circle"
	square   = "square"
	heptagon = "heptagon"
	hexagon  = "hexagon"
	cloud    = "cloud"

	Client54001EndpointID  = render.MakeEndpointID(fixture.ClientHostID, fixture.ClientIP, fixture.ClientPort54001)
	Client54002EndpointID  = render.MakeEndpointID(fixture.ClientHostID, fixture.ClientIP, fixture.ClientPort54002)
	ServerEndpointID       = render.MakeEndpointID(fixture.ServerHostID, fixture.ServerIP, fixture.ServerPort)
	NonContainerEndpointID = render.MakeEndpointID(fixture.ServerHostID, fixture.ServerIP, fixture.NonContainerClientPort)

	uncontainedServerID  = render.MakePseudoNodeID(render.UncontainedID, fixture.ServerHostName)
	unknownPseudoNode1ID = render.MakePseudoNodeID("10.10.10.10", fixture.ServerIP, "80")
	unknownPseudoNode2ID = render.MakePseudoNodeID("10.10.10.11", fixture.ServerIP, "80")

	RenderedEndpoints = (render.RenderableNodes{
		Client54001EndpointID: {
			ID:         Client54001EndpointID,
			LabelMajor: net.JoinHostPort(fixture.ClientIP, fixture.ClientPort54001),
			LabelMinor: fmt.Sprintf("%s (%s)", fixture.ClientHostID, fixture.Client1PID),
			Shape:      circle,
			Node:       report.MakeNode().WithAdjacent(ServerEndpointID),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount: newu64(10),
				EgressByteCount:   newu64(100),
			},
		},
		Client54002EndpointID: {
			ID:         Client54002EndpointID,
			LabelMajor: net.JoinHostPort(fixture.ClientIP, fixture.ClientPort54002),
			LabelMinor: fmt.Sprintf("%s (%s)", fixture.ClientHostID, fixture.Client2PID),
			Shape:      circle,
			Node:       report.MakeNode().WithAdjacent(ServerEndpointID),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount: newu64(20),
				EgressByteCount:   newu64(200),
			},
		},
		ServerEndpointID: {
			ID:         ServerEndpointID,
			LabelMajor: net.JoinHostPort(fixture.ServerIP, fixture.ServerPort),
			LabelMinor: fmt.Sprintf("%s (%s)", fixture.ServerHostID, fixture.ServerPID),
			Shape:      circle,
			Node:       report.MakeNode(),
			EdgeMetadata: report.EdgeMetadata{
				IngressPacketCount: newu64(210),
				IngressByteCount:   newu64(2100),
			},
		},
		NonContainerEndpointID: {
			ID:         NonContainerEndpointID,
			LabelMajor: net.JoinHostPort(fixture.ServerIP, fixture.NonContainerClientPort),
			LabelMinor: fmt.Sprintf("%s (%s)", fixture.ServerHostID, fixture.NonContainerPID),
			Shape:      circle,
			Node:       report.MakeNode().WithAdjacent(render.TheInternetID),
		},
		unknownPseudoNode1ID: {
			ID:         unknownPseudoNode1ID,
			LabelMajor: "10.10.10.10",
			Pseudo:     true,
			Shape:      circle,
			Node:       report.MakeNode().WithAdjacent(ServerEndpointID),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount: newu64(70),
				EgressByteCount:   newu64(700),
			},
		},
		unknownPseudoNode2ID: {
			ID:         unknownPseudoNode2ID,
			LabelMajor: "10.10.10.11",
			Pseudo:     true,
			Shape:      circle,
			Node:       report.MakeNode().WithAdjacent(ServerEndpointID),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount: newu64(50),
				EgressByteCount:   newu64(500),
			},
		},
		render.TheInternetID: {
			ID:         render.TheInternetID,
			LabelMajor: render.TheInternetMajor,
			Pseudo:     true,
			Shape:      cloud,
			Node:       report.MakeNode().WithAdjacent(ServerEndpointID),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount: newu64(60),
				EgressByteCount:   newu64(600),
			},
		},
	}).Prune()

	unknownPseudoNode1 = func(adjacent string) render.RenderableNode {
		return render.RenderableNode{
			ID:         unknownPseudoNode1ID,
			LabelMajor: "10.10.10.10",
			Pseudo:     true,
			Shape:      circle,
			Node:       report.MakeNode().WithAdjacent(adjacent),
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[unknownPseudoNode1ID],
			),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount: newu64(70),
				EgressByteCount:   newu64(700),
			},
		}
	}
	unknownPseudoNode2 = func(adjacent string) render.RenderableNode {
		return render.RenderableNode{
			ID:         unknownPseudoNode2ID,
			LabelMajor: "10.10.10.11",
			Pseudo:     true,
			Shape:      circle,
			Node:       report.MakeNode().WithAdjacent(adjacent),
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[unknownPseudoNode2ID],
			),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount: newu64(50),
				EgressByteCount:   newu64(500),
			},
		}
	}
	theInternetNode = func(adjacent string) render.RenderableNode {
		return render.RenderableNode{
			ID:         render.TheInternetID,
			LabelMajor: render.TheInternetMajor,
			Pseudo:     true,
			Shape:      cloud,
			Node:       report.MakeNode().WithAdjacent(adjacent),
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[render.TheInternetID],
			),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount: newu64(60),
				EgressByteCount:   newu64(600),
			},
		}
	}

	ClientProcess1ID      = render.MakeProcessID(fixture.ClientHostID, fixture.Client1PID)
	ClientProcess2ID      = render.MakeProcessID(fixture.ClientHostID, fixture.Client2PID)
	ServerProcessID       = render.MakeProcessID(fixture.ServerHostID, fixture.ServerPID)
	nonContainerProcessID = render.MakeProcessID(fixture.ServerHostID, fixture.NonContainerPID)

	RenderedProcesses = (render.RenderableNodes{
		ClientProcess1ID: {
			ID:         ClientProcess1ID,
			LabelMajor: fixture.Client1Name,
			LabelMinor: fmt.Sprintf("%s (%s)", fixture.ClientHostID, fixture.Client1PID),
			Rank:       fixture.Client1Name,
			Pseudo:     false,
			Shape:      square,
			Node:       report.MakeNode().WithAdjacent(ServerProcessID),
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[Client54001EndpointID],
			),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount: newu64(10),
				EgressByteCount:   newu64(100),
			},
		},
		ClientProcess2ID: {
			ID:         ClientProcess2ID,
			LabelMajor: fixture.Client2Name,
			LabelMinor: fmt.Sprintf("%s (%s)", fixture.ClientHostID, fixture.Client2PID),
			Rank:       fixture.Client2Name,
			Pseudo:     false,
			Shape:      square,
			Node:       report.MakeNode().WithAdjacent(ServerProcessID),
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[Client54002EndpointID],
			),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount: newu64(20),
				EgressByteCount:   newu64(200),
			},
		},
		ServerProcessID: {
			ID:         ServerProcessID,
			LabelMajor: fixture.ServerName,
			LabelMinor: fmt.Sprintf("%s (%s)", fixture.ServerHostID, fixture.ServerPID),
			Rank:       fixture.ServerName,
			Pseudo:     false,
			Shape:      square,
			Node:       report.MakeNode(),
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[ServerEndpointID],
			),
			EdgeMetadata: report.EdgeMetadata{
				IngressPacketCount: newu64(210),
				IngressByteCount:   newu64(2100),
			},
		},
		nonContainerProcessID: {
			ID:         nonContainerProcessID,
			LabelMajor: fixture.NonContainerName,
			LabelMinor: fmt.Sprintf("%s (%s)", fixture.ServerHostID, fixture.NonContainerPID),
			Rank:       fixture.NonContainerName,
			Pseudo:     false,
			Shape:      square,
			Node:       report.MakeNode().WithAdjacent(render.TheInternetID),
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[NonContainerEndpointID],
			),
			EdgeMetadata: report.EdgeMetadata{},
		},
		unknownPseudoNode1ID: unknownPseudoNode1(ServerProcessID),
		unknownPseudoNode2ID: unknownPseudoNode2(ServerProcessID),
		render.TheInternetID: theInternetNode(ServerProcessID),
	}).Prune()

	RenderedProcessNames = (render.RenderableNodes{
		fixture.Client1Name: {
			ID:         fixture.Client1Name,
			LabelMajor: fixture.Client1Name,
			LabelMinor: "2 processes",
			Rank:       fixture.Client1Name,
			Pseudo:     false,
			Shape:      square,
			Stack:      true,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[Client54001EndpointID],
				RenderedEndpoints[Client54002EndpointID],
				RenderedProcesses[ClientProcess1ID],
				RenderedProcesses[ClientProcess2ID],
			),
			Node: report.MakeNode().WithAdjacent(fixture.ServerName),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount: newu64(30),
				EgressByteCount:   newu64(300),
			},
		},
		fixture.ServerName: {
			ID:         fixture.ServerName,
			LabelMajor: fixture.ServerName,
			LabelMinor: "1 process",
			Rank:       fixture.ServerName,
			Pseudo:     false,
			Shape:      square,
			Stack:      true,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[ServerEndpointID],
				RenderedProcesses[ServerProcessID],
			),
			Node: report.MakeNode(),
			EdgeMetadata: report.EdgeMetadata{
				IngressPacketCount: newu64(210),
				IngressByteCount:   newu64(2100),
			},
		},
		fixture.NonContainerName: {
			ID:         fixture.NonContainerName,
			LabelMajor: fixture.NonContainerName,
			LabelMinor: "1 process",
			Rank:       fixture.NonContainerName,
			Pseudo:     false,
			Shape:      square,
			Stack:      true,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[NonContainerEndpointID],
				RenderedProcesses[nonContainerProcessID],
			),
			Node:         report.MakeNode().WithAdjacent(render.TheInternetID),
			EdgeMetadata: report.EdgeMetadata{},
		},
		unknownPseudoNode1ID: unknownPseudoNode1(fixture.ServerName),
		unknownPseudoNode2ID: unknownPseudoNode2(fixture.ServerName),
		render.TheInternetID: theInternetNode(fixture.ServerName),
	}).Prune()

	ClientContainerID = render.MakeContainerID(fixture.ClientContainerID)
	ServerContainerID = render.MakeContainerID(fixture.ServerContainerID)

	RenderedContainers = (render.RenderableNodes{
		ClientContainerID: {
			ID:         ClientContainerID,
			LabelMajor: "client",
			LabelMinor: fixture.ClientHostName,
			Pseudo:     false,
			Shape:      hexagon,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[Client54001EndpointID],
				RenderedEndpoints[Client54002EndpointID],
				RenderedProcesses[ClientProcess1ID],
				RenderedProcesses[ClientProcess2ID],
			),
			Node: report.MakeNode().WithAdjacent(ServerContainerID),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount: newu64(30),
				EgressByteCount:   newu64(300),
			},
			ControlNode: fixture.ClientContainerNodeID,
		},
		ServerContainerID: {
			ID:         ServerContainerID,
			LabelMajor: "server",
			LabelMinor: fixture.ServerHostName,
			Pseudo:     false,
			Shape:      hexagon,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[ServerEndpointID],
				RenderedProcesses[ServerProcessID],
			),
			Node: report.MakeNode(),
			EdgeMetadata: report.EdgeMetadata{
				IngressPacketCount: newu64(210),
				IngressByteCount:   newu64(2100),
			},
			ControlNode: fixture.ServerContainerNodeID,
		},
		uncontainedServerID: {
			ID:         uncontainedServerID,
			LabelMajor: render.UncontainedMajor,
			LabelMinor: fixture.ServerHostName,
			Pseudo:     true,
			Shape:      square,
			Stack:      true,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[NonContainerEndpointID],
				RenderedProcesses[nonContainerProcessID],
			),
			Node:         report.MakeNode().WithAdjacent(render.TheInternetID),
			EdgeMetadata: report.EdgeMetadata{},
		},
		unknownPseudoNode1ID: unknownPseudoNode1(ServerContainerID),
		unknownPseudoNode2ID: unknownPseudoNode2(ServerContainerID),
		render.TheInternetID: theInternetNode(ServerContainerID),
	}).Prune()

	ClientContainerImageID = render.MakeContainerImageID(fixture.ClientContainerImageName)
	ServerContainerImageID = render.MakeContainerImageID(fixture.ServerContainerImageName)

	RenderedContainerImages = (render.RenderableNodes{
		ClientContainerImageID: {
			ID:         ClientContainerImageID,
			LabelMajor: fixture.ClientContainerImageName,
			LabelMinor: "1 container",
			Rank:       fixture.ClientContainerImageName,
			Pseudo:     false,
			Shape:      hexagon,
			Stack:      true,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[Client54001EndpointID],
				RenderedEndpoints[Client54002EndpointID],
				RenderedProcesses[ClientProcess1ID],
				RenderedProcesses[ClientProcess2ID],
				RenderedContainers[ClientContainerID],
			),
			Node: report.MakeNode().WithAdjacent(ServerContainerImageID),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount: newu64(30),
				EgressByteCount:   newu64(300),
			},
		},
		ServerContainerImageID: {
			ID:         ServerContainerImageID,
			LabelMajor: fixture.ServerContainerImageName,
			LabelMinor: "1 container",
			Rank:       fixture.ServerContainerImageName,
			Pseudo:     false,
			Shape:      hexagon,
			Stack:      true,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[ServerEndpointID],
				RenderedProcesses[ServerProcessID],
				RenderedContainers[ServerContainerID],
			),
			Node: report.MakeNode(),
			EdgeMetadata: report.EdgeMetadata{
				IngressPacketCount: newu64(210),
				IngressByteCount:   newu64(2100),
			},
		},
		uncontainedServerID: {
			ID:         uncontainedServerID,
			LabelMajor: render.UncontainedMajor,
			LabelMinor: fixture.ServerHostName,
			Pseudo:     true,
			Shape:      square,
			Stack:      true,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[NonContainerEndpointID],
				RenderedProcesses[nonContainerProcessID],
			),
			Node:         report.MakeNode().WithAdjacent(render.TheInternetID),
			EdgeMetadata: report.EdgeMetadata{},
		},
		unknownPseudoNode1ID: unknownPseudoNode1(ServerContainerImageID),
		unknownPseudoNode2ID: unknownPseudoNode2(ServerContainerImageID),
		render.TheInternetID: theInternetNode(ServerContainerImageID),
	}).Prune()

	ClientAddressID         = render.MakeAddressID(fixture.ClientHostID, fixture.ClientIP)
	ServerAddressID         = render.MakeAddressID(fixture.ServerHostID, fixture.ServerIP)
	unknownPseudoAddress1ID = render.MakePseudoNodeID("10.10.10.10", fixture.ServerIP)
	unknownPseudoAddress2ID = render.MakePseudoNodeID("10.10.10.11", fixture.ServerIP)

	RenderedAddresses = (render.RenderableNodes{
		ClientAddressID: {
			ID:         ClientAddressID,
			LabelMajor: fixture.ClientIP,
			LabelMinor: fixture.ClientHostID,
			Shape:      circle,
			Node:       report.MakeNode().WithAdjacent(ServerAddressID),
		},
		ServerAddressID: {
			ID:         ServerAddressID,
			LabelMajor: fixture.ServerIP,
			LabelMinor: fixture.ServerHostID,
			Shape:      circle,
			Node:       report.MakeNode(),
		},
		unknownPseudoAddress1ID: {
			ID:         unknownPseudoAddress1ID,
			LabelMajor: "10.10.10.10",
			Pseudo:     true,
			Shape:      circle,
			Node:       report.MakeNode().WithAdjacent(ServerAddressID),
		},
		unknownPseudoAddress2ID: {
			ID:         unknownPseudoAddress2ID,
			LabelMajor: "10.10.10.11",
			Pseudo:     true,
			Shape:      circle,
			Node:       report.MakeNode().WithAdjacent(ServerAddressID),
		},
		render.TheInternetID: {
			ID:         render.TheInternetID,
			LabelMajor: render.TheInternetMajor,
			Pseudo:     true,
			Shape:      cloud,
			Node:       report.MakeNode().WithAdjacent(ServerAddressID),
		},
	}).Prune()

	ServerHostID  = render.MakeHostID(fixture.ServerHostID)
	ClientHostID  = render.MakeHostID(fixture.ClientHostID)
	pseudoHostID1 = render.MakePseudoNodeID(fixture.UnknownClient1IP, fixture.ServerIP)
	pseudoHostID2 = render.MakePseudoNodeID(fixture.UnknownClient3IP, fixture.ServerIP)

	RenderedHosts = (render.RenderableNodes{
		ClientHostID: {
			ID:         ClientHostID,
			LabelMajor: "client",       // before first .
			LabelMinor: "hostname.com", // after first .
			Rank:       "hostname.com",
			Pseudo:     false,
			Shape:      circle,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[Client54001EndpointID],
				RenderedEndpoints[Client54002EndpointID],
				RenderedProcesses[ClientProcess1ID],
				RenderedProcesses[ClientProcess2ID],
				RenderedContainers[ClientContainerID],
				RenderedContainerImages[ClientContainerImageID],
				RenderedAddresses[ClientAddressID],
			),
			Node: report.MakeNode().WithAdjacent(ServerHostID),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount: newu64(30),
				EgressByteCount:   newu64(300),
			},
		},
		ServerHostID: {
			ID:         ServerHostID,
			LabelMajor: "server",       // before first .
			LabelMinor: "hostname.com", // after first .
			Rank:       "hostname.com",
			Pseudo:     false,
			Shape:      circle,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[ServerEndpointID],
				RenderedProcesses[ServerProcessID],
				RenderedContainers[ServerContainerID],
				RenderedContainerImages[ServerContainerImageID],
				RenderedAddresses[ServerAddressID],
			),
			Node: report.MakeNode(),
			EdgeMetadata: report.EdgeMetadata{
				IngressPacketCount: newu64(210),
				IngressByteCount:   newu64(2100),
			},
		},

		pseudoHostID1: {
			ID:           pseudoHostID1,
			LabelMajor:   fixture.UnknownClient1IP,
			Pseudo:       true,
			Shape:        circle,
			Node:         report.MakeNode().WithAdjacent(ServerHostID),
			EdgeMetadata: report.EdgeMetadata{},
			Children:     render.MakeRenderableNodeSet(
			//TODO
			//RenderedEndpoints[unknownPseudoNode2ID],
			//RenderedAddresses[unknownPseudoAddress1ID],
			),
		},
		pseudoHostID2: {
			ID:           pseudoHostID2,
			LabelMajor:   fixture.UnknownClient3IP,
			Pseudo:       true,
			Shape:        circle,
			Node:         report.MakeNode().WithAdjacent(ServerHostID),
			EdgeMetadata: report.EdgeMetadata{},
			Children:     render.MakeRenderableNodeSet(
			//RenderedEndpoints[unknownPseudoNode2ID],
			//RenderedAddresses[unknownPseudoAddress2ID],
			),
		},
		render.TheInternetID: {
			ID:           render.TheInternetID,
			LabelMajor:   render.TheInternetMajor,
			Pseudo:       true,
			Shape:        cloud,
			Node:         report.MakeNode().WithAdjacent(ServerHostID),
			EdgeMetadata: report.EdgeMetadata{},
			Children:     render.MakeRenderableNodeSet(
			//RenderedEndpoints[render.TheInternetID],
			),
		},
	}).Prune()

	ClientPodRenderedID = render.MakePodID("ping/pong-a")
	ServerPodRenderedID = render.MakePodID("ping/pong-b")

	RenderedPods = (render.RenderableNodes{
		ClientPodRenderedID: {
			ID:         ClientPodRenderedID,
			LabelMajor: "pong-a",
			LabelMinor: "1 container",
			Rank:       "ping/pong-a",
			Pseudo:     false,
			Shape:      heptagon,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[Client54001EndpointID],
				RenderedEndpoints[Client54002EndpointID],
				RenderedProcesses[ClientProcess1ID],
				RenderedProcesses[ClientProcess2ID],
				RenderedContainers[ClientContainerID],
			),
			Node: report.MakeNode().WithAdjacent(ServerPodRenderedID),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount: newu64(30),
				EgressByteCount:   newu64(300),
			},
		},
		ServerPodRenderedID: {
			ID:         ServerPodRenderedID,
			LabelMajor: "pong-b",
			LabelMinor: "1 container",
			Rank:       "ping/pong-b",
			Pseudo:     false,
			Shape:      heptagon,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[ServerEndpointID],
				RenderedProcesses[ServerProcessID],
				RenderedContainers[ServerContainerID],
			),
			Node: report.MakeNode(),
			EdgeMetadata: report.EdgeMetadata{
				IngressPacketCount: newu64(210),
				IngressByteCount:   newu64(2100),
			},
		},
		uncontainedServerID: {
			ID:         uncontainedServerID,
			LabelMajor: render.UncontainedMajor,
			LabelMinor: fixture.ServerHostName,
			Pseudo:     true,
			Shape:      square,
			Stack:      true,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[NonContainerEndpointID],
				RenderedProcesses[nonContainerProcessID],
			),
			Node:         report.MakeNode().WithAdjacent(render.TheInternetID),
			EdgeMetadata: report.EdgeMetadata{},
		},
		unknownPseudoNode1ID: unknownPseudoNode1(ServerPodRenderedID),
		unknownPseudoNode2ID: unknownPseudoNode2(ServerPodRenderedID),
		render.TheInternetID: theInternetNode(ServerPodRenderedID),
	}).Prune()

	ServiceRenderedID = render.MakeServiceID("ping/pongservice")

	RenderedPodServices = (render.RenderableNodes{
		ServiceRenderedID: {
			ID:         ServiceRenderedID,
			LabelMajor: "pongservice",
			LabelMinor: "2 pods",
			Rank:       fixture.ServiceID,
			Pseudo:     false,
			Shape:      heptagon,
			Stack:      true,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[Client54001EndpointID],
				RenderedEndpoints[Client54002EndpointID],
				RenderedEndpoints[ServerEndpointID],
				RenderedProcesses[ClientProcess1ID],
				RenderedProcesses[ClientProcess2ID],
				RenderedProcesses[ServerProcessID],
				RenderedContainers[ClientContainerID],
				RenderedContainers[ServerContainerID],
				RenderedPods[ClientPodRenderedID],
				RenderedPods[ServerPodRenderedID],
			),
			Node: report.MakeNode().WithAdjacent(ServiceRenderedID),
			EdgeMetadata: report.EdgeMetadata{
				EgressPacketCount:  newu64(30),
				EgressByteCount:    newu64(300),
				IngressPacketCount: newu64(210),
				IngressByteCount:   newu64(2100),
			},
		},
		uncontainedServerID: {
			ID:         uncontainedServerID,
			LabelMajor: render.UncontainedMajor,
			LabelMinor: fixture.ServerHostName,
			Pseudo:     true,
			Shape:      square,
			Stack:      true,
			Children: render.MakeRenderableNodeSet(
				RenderedEndpoints[NonContainerEndpointID],
				RenderedProcesses[nonContainerProcessID],
			),
			Node:         report.MakeNode().WithAdjacent(render.TheInternetID),
			EdgeMetadata: report.EdgeMetadata{},
		},
		unknownPseudoNode1ID: unknownPseudoNode1(ServiceRenderedID),
		unknownPseudoNode2ID: unknownPseudoNode2(ServiceRenderedID),
		render.TheInternetID: theInternetNode(ServiceRenderedID),
	}).Prune()
)

func newu64(value uint64) *uint64 { return &value }
