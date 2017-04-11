package appclient

import (
	"bytes"
	"compress/gzip"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/weaveworks/scope/report"
	"io/ioutil"
	"time"
)

// A ReportPublisher uses a buffer pool to serialise reports, which it
// then passes to a publisher
type ReportPublisher struct {
	publisher  Publisher
	noControls bool
}

// NewReportPublisher creates a new report publisher
func NewReportPublisher(publisher Publisher, noControls bool) *ReportPublisher {
	return &ReportPublisher{
		publisher:  publisher,
		noControls: noControls,
	}
}

// Publish serialises and compresses a report, then passes it to a publisher
func (p *ReportPublisher) Publish(r report.Report) error {
	if p.noControls {
		r.WalkTopologies(func(t *report.Topology) {
			t.Controls = report.Controls{}
		})
	}

	for level := gzip.DefaultCompression; level <= gzip.BestCompression; level++ {
		allTmpBuf := []*bytes.Buffer{}
		start := time.Now()
		for i := 0; i < 10; i++ {
			tmpBuf := &bytes.Buffer{}
			r.WriteBinary(tmpBuf, level)
			allTmpBuf = append(allTmpBuf, tmpBuf)
		}
		elapsed := time.Since(start)

		log.Infof("Report: level=%d Len=%d Elapsed=%s", level, allTmpBuf[0].Len(), elapsed)
		ioutil.WriteFile(fmt.Sprintf("/tmp/report_%d", level), allTmpBuf[0].Bytes(), 0644)
	}

	buf := &bytes.Buffer{}
	r.WriteBinary(buf, gzip.BestCompression)
	return p.publisher.Publish(buf)
}
