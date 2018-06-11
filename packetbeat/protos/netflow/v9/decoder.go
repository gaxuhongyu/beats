package v9

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
)

var (
	errProtocol   = errors.New("Protocol error")
	errTemplateID = errors.New("Template id not found")
	errTemplate   = errors.New("Template Error")
	debugf        = logp.MakeDebug("NetFlow v9")
)

// TemplateInfo save Template data
var TemplateInfo sync.Map

// Decoder represents v9 decoder
type Decoder struct {
	reader io.ReadSeeker
	t      time.Time
	SrcIP  net.IP
}

func init() {
	TemplateInfo = sync.Map{}
}

// NewDecoder factory function
func NewDecoder(r io.ReadSeeker, t time.Time, ip net.IP) *Decoder {
	return &Decoder{r, t, ip}
}

// Decode Decode netflow v9
func (d *Decoder) Decode() (*Packet, error) {
	var (
		p   *Packet
		err error
	)
	p = &Packet{t: d.t}
	if err = p.Header.Unmarshal(d.reader); err != nil {
		debugf("Unmarshal packet header error: %s", err.Error())
		return nil, err
	}
	debugf("Packet header : %X", p.Header)
	for i := uint16(0); i < p.Header.Count; i++ {
		fsh := &FlowSetHeader{}
		if err = fsh.Unmarshal(d.reader); err != nil {
			debugf("Unmarshal Flow Set Header Error: %s", err.Error())
			return nil, err
		}
		debugf("Flow Set Header: %X", fsh)
		// debugf("Reader Data: %X", d.reader)
		if fsh.ID == 0 {
			tfs := &TemplateFlowSet{}
			if err = tfs.Records.Unmarshal(d.reader); err != nil {
				debugf("Unmarshal Template Flow Set Error: %s", err.Error())
				return nil, err
			}
			tfs.Header = *fsh
			debugf("Template Flow Set: %X", tfs)
			debugf(fmt.Sprintf("%s-%X", d.SrcIP.String(), tfs.Records.TemplateID))
			p.TemplateFlowSets = append(p.TemplateFlowSets, tfs)
			TemplateInfo.Store(fmt.Sprintf("%s-%X", d.SrcIP.String(), tfs.Records.TemplateID), tfs)
		} else if fsh.ID == 1 {
			otfs := &OptionsTemplateFlowSet{}
			otfs.Header = *fsh
			if err = otfs.Unmarshal(d.reader); err != nil {
				debugf("Unmarshal Options Template Flow Set Error: %s", err.Error())
				return nil, err
			}
			debugf("Options Template Flow Set: %X", otfs)
			debugf(fmt.Sprintf("%s-%X", d.SrcIP.String(), otfs.TemplateID))
			p.OptionsTemplateFlowSets = append(p.OptionsTemplateFlowSets, otfs)
			TemplateInfo.Store(fmt.Sprintf("%s-%X", d.SrcIP.String(), otfs.TemplateID), otfs)
		} else if fsh.ID > 255 {
			dfs := &DataFlowSet{}
			dfs.Header = fsh
			template, ok := TemplateInfo.Load(fmt.Sprintf("%s-%X", d.SrcIP.String(), fsh.ID))
			if ok && template != nil {
				if err = dfs.Unmarshal(d.reader, template); err != nil {
					debugf("Unmarshal Data Flow Set Error: %s", err.Error())
					return nil, err
				}
				debugf("Data Flow Set:%X", dfs)
				p.DataFlowSets = append(p.DataFlowSets, dfs)
			} else {
				debugf("Template ID: %X Not Found", fsh.ID)
				d.reader.Seek(int64(fsh.Length-fsh.Len()), 1)
			}
		} else {
			return nil, errTemplateID
		}
	}
	return p, nil
}

// TransInfo Netflow v9 TransInfo
func (p *Packet) TransInfo() []common.MapStr {
	res := make([]common.MapStr, 0)
	for _, v := range p.DataFlowSets {
		event := common.MapStr{
			"type":    "netflow",
			"version": 9,
			// "Timestamp": p.t,
			// "systemUpTime": time.Unix(int64(p.Header.UnixSecs), 0),
		}
		for _, vv := range v.Records {
			t := fmt.Sprintf("%d", vv.Type)
			if f := filedsInfo[t]; f != nil {
				if rs := f.Value(vv.Bytes); rs != nil {
					event[f.Name] = rs
				}
			}
		}
		res = append(res, event)
	}
	return res
}
