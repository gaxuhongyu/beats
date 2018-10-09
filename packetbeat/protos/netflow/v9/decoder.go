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

// OptionDataInfo Option data
var OptionDataInfo sync.Map

// Template Interface
type Template interface {
	DataLength() uint16
	GetFields() []FieldSpecifier
	GetFieldCount() uint16
	Length() uint16
}

// Decoder represents v9 decoder
type Decoder struct {
	reader io.ReadSeeker
	t      time.Time
	SrcIP  net.IP
}

func init() {
	TemplateInfo = sync.Map{}
	OptionDataInfo = sync.Map{}
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
	p = &Packet{t: d.t, SrcIP: d.SrcIP}
	if err = p.Header.Unmarshal(d.reader); err != nil {
		debugf("Unmarshal packet header error: %s", err.Error())
		return nil, err
	}
	debugf("流条数:%d", p.Header.Count)
	debugf("Packet header : %X", p.Header)
	for index := uint16(0); index < p.Header.Count; {
		fsh := &FlowSetHeader{}
		if err = fsh.Unmarshal(d.reader); err != nil {
			debugf("Unmarshal Flow Set Header Error: %s", err.Error())
			return nil, err
		}
		debugf("Flow Set Header: %X", fsh)
		if fsh.ID == 0 {
			tfs := &TemplateFlowSet{}
			tfs.Header = fsh
			if err = tfs.Unmarshal(d.reader); err != nil {
				debugf("Unmarshal Template Flow Set Error: %s", err.Error())
				return nil, err
			}
			debugf("Template Flow Set: %X", tfs)
			p.TemplateFlowSets = tfs
			for _, v := range tfs.Records {
				temp := fmt.Sprintf("%s-%d", d.SrcIP.String(), v.TemplateID)
				debugf(temp)
				if _, ok := TemplateInfo.Load(temp); ok {
					TemplateInfo.Delete(temp)
				}
				TemplateInfo.Store(temp, v)
			}
			index = index + uint16(len(tfs.Records))
		} else if fsh.ID == 1 {
			otfs := &OptionsTemplateFlowSet{}
			otfs.Header = fsh
			if err = otfs.Unmarshal(d.reader); err != nil {
				debugf("Unmarshal Options Template Flow Set Error: %s", err.Error())
				return nil, err
			}
			debugf("Options Template Flow Set: %X", otfs)
			temp := fmt.Sprintf("%s-%d", d.SrcIP.String(), otfs.TemplateID)
			debugf(temp)
			p.OptionsTemplateFlowSets = otfs
			if _, ok := TemplateInfo.Load(temp); ok {
				TemplateInfo.Delete(temp)
			}
			TemplateInfo.Store(temp, otfs)
			index++
		} else if fsh.ID > 255 {
			template, ok := TemplateInfo.Load(fmt.Sprintf("%s-%d", d.SrcIP.String(), fsh.ID))
			if ok && template != nil {
				var dLen uint16
				t := template.(Template)
				count := fsh.Length / t.DataLength()
				debugf("Count:%d", count)
				for i := uint16(0); i < count; i++ {
					dfs := &DataFlowSet{}
					dfs.Header = fsh
					if err = dfs.Unmarshal(d.reader, t); err != nil {
						debugf("Unmarshal Data Flow Set Error: %s", err.Error())
						return nil, err
					}
					debugf("Data Flow Set:%X", dfs)
					switch template.(type) {
					case *TemplateRecord:
						p.DataFlowSets = append(p.DataFlowSets, dfs)
					case *OptionsTemplateFlowSet:
						var data map[string]*DataFlowSet
						tid := template.(*OptionsTemplateFlowSet).TemplateID
						TemplateID := fmt.Sprintf("%s-%d", d.SrcIP.String(), tid)
						value, ok := OptionDataInfo.Load(d.SrcIP.String())
						if ok && value != nil {
							debugf("Update %s Options Template :%X", d.SrcIP.String(), tid)
							data = value.(map[string]*DataFlowSet)
							data[TemplateID] = dfs
							debugf("%s Options Template Count: %d", d.SrcIP.String(), len(data))
						} else {
							debugf("Save %s Options Template :%X", d.SrcIP.String(), tid)
							data = make(map[string]*DataFlowSet)
							data[TemplateID] = dfs
							debugf("%s Options Template Count: %d", d.SrcIP.String(), len(data))
						}
						OptionDataInfo.Store(d.SrcIP.String(), data)
					}
					dLen = dLen + t.DataLength()
				}
				index = index + count
				// skip padding
				d.reader.Seek(int64(fsh.Length-fsh.Len()-dLen), 1)
			} else {
				debugf("Template ID: %X Not Found", fsh.ID)
				d.reader.Seek(int64(fsh.Length-fsh.Len()), 1)
			}
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
		}
		// FlowSet, ok := TemplateInfo.Load(p.SrcIP.String())
		value, ok := OptionDataInfo.Load(p.SrcIP.String())
		if ok && value != nil {
			data := value.(map[string]*DataFlowSet)
			for _, v := range data {
				for _, f1 := range v.Records {
					t := fmt.Sprintf("%d", f1.Type)
					if f2 := filedsInfo[t]; f2 != nil && len(f1.Bytes) > 0 {
						if rs := f2.Value(f1.Bytes, f1.Length); rs != nil {
							event[f2.Name] = rs
						}
					}
				}
			}
		}
		for _, vv := range v.Records {
			t := fmt.Sprintf("%d", vv.Type)
			if f := filedsInfo[t]; f != nil && len(vv.Bytes) > 0 {
				if rs := f.Value(vv.Bytes, vv.Length); rs != nil {
					event[f.Name] = rs
				}
			}
		}
		res = append(res, event)
	}
	return res
}
