package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	hostname, _ := os.Hostname()
	var (
		addr   = flag.String("addr", "/var/run/scope/plugins/iowait.sock", "unix socket to listen for connections on")
		hostID = flag.String("hostname", hostname, "hostname of the host running this plugin")
	)
	flag.Parse()

	log.Printf("Starting on %s...\n", *hostID)

	// Check we can get the iowait for the system
	_, err := iowait()
	if err != nil {
		log.Fatal(err)
	}

	os.Remove(*addr)
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	go func() {
		<-interrupt
		os.Remove(*addr)
		os.Exit(0)
	}()

	listener, err := net.Listen("unix", *addr)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		listener.Close()
		os.Remove(*addr)
	}()

	log.Printf("Listening on: unix://%s", *addr)

	plugin := &Plugin{HostID: *hostID}
	http.HandleFunc("/report", plugin.Report)
	http.HandleFunc("/control", plugin.Control)
	if err := http.Serve(listener, nil); err != nil {
		log.Printf("error: %v", err)
	}
}

// Plugin groups the methods a plugin needs
type Plugin struct {
	HostID string

	lock       sync.Mutex
	iowaitMode bool
}

type request struct {
	NodeID  string
	Control string
}

type response struct {
	ShortcutReport *report `json:"shortcutReport,omitempty"`
}

type report struct {
	Host topology
	Plugins []pluginSpec
}

type topology struct {
	Nodes map[string]node `json:"nodes"`
	MetricTemplates map[string]metricTemplate`json:"metric_templates"`
	Controls map[string]control `json:"controls"`
}

type node struct {
	Metrics  map[string]metric `json:"metrics"`
	LatestControls latestNodeControls `json:"latestControls"`
}

type metric struct {
	Samples []sample `json:"samples,omitempty"`
	Min     float64  `json:"min"`
	Max     float64  `json:"max"`
}

type sample struct {
	Date  time.Time `json:"date"`
	Value float64   `json:"value"`
}

type latestNodeControls {
	LatestMap map[string]controlEntry `json:"latest,omitempty`
}

type controlEntry struct {
	Timestamp time.Time   `json:"timestamp"`
	Value     controlData `json:"value"`
}

type controlData {
	Dead bool `json:"dead,omitempty`
}

type metricTemplate struct {
	ID       string  `json:"id"`
	Label    string  `json:"label,omitempty"`
	Format   string  `json:"format,omitempty"`
	Priority float64 `json:"priority,omitempty"`
}

type control struct {
	ID    string `json:"id"`
	Human string `json:"human"`
	Icon  string `json:"icon"`
	Rank  int    `json:"rank"`
}

type pluginSpec struct {
	ID string `json:"id"`
	Label string `json:"label"`
	Description string `json:"description,omitempty"`
	Interfaces []string `json:"interfaces"`
	APIVersion string `json:"api_version,omitempty"`
}

func (p *Plugin) makeReport() (*report, error) {
	metrics, err := p.metrics()
	if err != nil {
		return nil, err
	}
	return &report{
		Host: topology{
			Nodes: map[string]node{
				p.getTopologyHost(): node{
					Metrics:  metrics,
					Controls: p.nodeControls(),
				},
			},
			MetricTemplates: p.metricTemplates(),
			Controls: p.controls()
		},
		Plugins: pluginSpec {
			ID: "iowait",
			Label: "iowait",
			Description: "Adds a graph of CPU IO Wait to hosts",
			Interfaces: ["reporter", "controller"],
			APIVersion: "1",
		},
	}
}

func (p *Plugin) metrics() (map[string]metric, error) {
	value, err := p.metricValue()
	if err != nil {
		return nil, err
	}
	id, name := p.metricIDAndName()
	return map[string]metric{
		id: metric{
			Samples: []sample{
				sample{
					Date:  time.Now(),
					Value: value,
				}
			}
			Min: 0,
			Max: 100,
		}
	}
}

func (p *Plugin) latestNodeControls() latestNodeControls {
	ts := time.Now()
	ctrls := map[string]controlEntry{}
	for _, details := range p.allControlDetails() {
		ctrls[details.id] = controlEntry {
			Timestamp: ts,
			Value: controlData{
				Dead: details.dead,
			}
		}
	}
	return latestNodeControls{
		LatestMap: ctrls
	}
}

func (p *Plugin) metricTemplates() map[string]metricTemplate {
	id, name := p.metricIDAndName()
	return map[string]metricTemplate{
		id: metricTemplate{
			ID: id,
			Label: name,
			Format:   "percent",
			Priority: 0.1,
		}
	}
}

func (p *Plugin) controls() map[string]control {
	ctrls := map[string]control{}
	for details := range p.allControlDetails() {
		ctrls[details.id] = control{
			ID: details.id,
			Human: details.human,
			Icon: details.icon,
			Rank: 1,
		}
	}
}

// Report is called by scope when a new report is needed. It is part of the
// "reporter" interface, which all plugins must implement.
func (p *Plugin) Report(w http.ResponseWriter, r *http.Request) {
	p.lock.Lock()
	defer p.lock.Unlock()
	log.Println(r.URL.String())
	rpt, err := p.makeReport()
	if err != nil {
		log.Printf("error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	raw, err := json.Marshal(*rpt)
	if err != nil {
		log.Printf("error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(raw)
}

// Control is called by scope when a control is activated. It is part
// of the "controller" interface.
func (p *Plugin) Control(w http.ResponseWriter, r *http.Request) {
	p.lock.Lock()
	defer p.lock.Unlock()
	log.Println(r.URL.String())
	xreq := request{}
	err := json.NewDecoder(r.Body).Decode(&xreq)
	if err != nil {
		log.Printf("Bad request: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	thisNodeID := p.getTopologyHost()
	if xreq.NodeID != thisNodeID {
		log.Printf("Bad nodeID, expected %q, got %q", thisNodeID, xreq.NodeID)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	expectedControlID, _, _ := p.controlDetails()
	if expectedControlID != xreq.Control {
		log.Printf("Bad control, expected %q, got %q", expectedControlID, xreq.Control)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	p.iowaitMode = !p.iowaitMode
	rpt, err := p.makeReport()
	if err != nil {
		log.Printf("error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	res := response{ShorcutReport: &rpt}
	raw, err := json.Marshal(res)
	if err != nil {
		log.Printf("error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(raw)
}

func (p *Plugin) getTopologyHost() string {
	return fmt.Sprintf("%s;<host>", p.HostID)
}

func (p *Plugin) metricIDAndName() (string, string) {
	if p.iowaitMode {
		return "iowait", "IO Wait"
	}
	return "idle", "Idle"
}

func (p *Plugin) metricValue() (float64, error) {
	if p.iowaitMode {
		return iowait()
	}
	return idle()
}

type controlDetails struct {
	id    string
	human string
	icon  string
	dead  bool
}

func (p *Plugin) allControlDetails() []controlDetails {
	return []controlDetails{
		controlDetails{
			id:    "switchToIdle",
			human: "Switch to idle",
			icon:  "fa-beer",
			dead:  !p.iowaitMode,
		},
		controlDetails{
			id:    "switchToIOWait",
			human: "Switch to IO wait",
			icon:  "fa-hourglass",
			dead:  p.iowaitMode,
		}
	}
}

func (p *Plugin) controlDetails() (string, string, string) {
	for _, details :=  range p.allControlDetails() {
		if !details.dead {
			return details.id, details.human, details.icon
		}
	}
	return "", "", ""
}

func iowait() (float64, error) {
	return iostatValue(3)
}

func idle() (float64, error) {
	return iostatValue(5)
}

func iostatValue(idx int) (float64, error) {
	values, err := iostat()
	if err != nil {
		return 0, err
	}
	if idx >= len(values) {
		return 0, fmt.Errorf("invalid iostat field index %d", idx)
	}

	return strconv.ParseFloat(values[idx], 64)
}

// Get the latest iostat values
func iostat() ([]string, error) {
	out, err := exec.Command("iostat", "-c").Output()
	if err != nil {
		return nil, fmt.Errorf("iowait: %v", err)
	}

	// Linux 4.2.0-25-generic (a109563eab38)	04/01/16	_x86_64_(4 CPU)
	//
	// avg-cpu:  %user   %nice %system %iowait  %steal   %idle
	//	          2.37    0.00    1.58    0.01    0.00   96.04
	lines := strings.Split(string(out), "\n")
	if len(lines) < 4 {
		return nil, fmt.Errorf("iowait: unexpected output: %q", out)
	}

	values := strings.Fields(lines[3])
	if len(values) != 6 {
		return nil, fmt.Errorf("iowait: unexpected output: %q", out)
	}
	return values, nil
}
