package v5

import (
	"io"
	"net"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
)

var (
	debugf = logp.MakeDebug("NetFlow v5")
)

// Decoder represents v9 decoder
type Decoder struct {
	reader io.ReadSeeker
	t      time.Time
	SrcIP  net.IP
}

// NewDecoder factory function
func NewDecoder(r io.ReadSeeker, t time.Time, ip net.IP) *Decoder {
	return &Decoder{r, t, ip}
}

// Decode Decode netflow v5
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
		f := &Flow{}
		if err = f.Unmarshal(d.reader); err != nil {
			debugf("Unmarshal Flow Error: %s", err.Error())
			return nil, err
		}
		p.Flows = append(p.Flows, f)
	}
	return p, nil
}

// TransInfo Netflow v5 TransInfo
func (p *Packet) TransInfo() []common.MapStr {
	res := make([]common.MapStr, 0)
	for _, v := range p.Flows {
		event := common.MapStr{
			"type":    "netflow",
			"version": 5,
		}
		v.TransInfo(event)
		res = append(res, event)
	}
	return res
}
