package detailed_test

import (
	"fmt"
	"testing"

	"github.com/weaveworks/scope/render"
	"github.com/weaveworks/scope/render/detailed"
	"github.com/weaveworks/scope/test"
	"github.com/weaveworks/scope/test/fixture"
	"github.com/weaveworks/scope/test/reflect"
)

func TestConnections(t *testing.T) {
	for _, c := range []struct {
		name   string
		nodes  render.RenderableNodes
		nodeID string
		want   map[string][]detailed.Connection
	}{
		{
			name:   "No Connections",
			nodes:  render.ProcessRenderer.Render(fixture.Report),
			nodeID: render.MakeProcessID(fixture.ClientHostID, fixture.NonContainerPID),
			want:   nil,
		},
		/*
			{
				name:   "Connections to the internet/pseudonodes",
				nodes:  render.HostRenderer.Render(fixture.Report),
				nodeID: render.MakeHostID(fixture.ClientHostID),
				want:   nil,
			},
			{
				name:   "Connections to itself",
				nodes:  render.HostRenderer.Render(fixture.Report),
				nodeID: render.MakeHostID(fixture.ClientHostID),
				want:   nil,
			},
			{
				name:   "Connections to other nodes",
				nodes:  render.HostRenderer.Render(fixture.Report),
				nodeID: render.MakeHostID(fixture.ClientHostID),
				want:   nil,
			},
		*/
	} {
		name := c.name
		if name == "" {
			name = fmt.Sprintf("Node %q", c.nodeID)
		}
		if have := detailed.Connections(fixture.Report, c.nodes[c.nodeID]); !reflect.DeepEqual(c.want, have) {
			t.Errorf("%s: %s", name, test.Diff(c.want, have))
		}
	}
}
