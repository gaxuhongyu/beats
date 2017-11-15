package sflow

import (
	"io"
	"net"

	"github.com/elastic/beats/libbeat/common"
)

// SFExtRouterData Extended router data
type SFExtRouterData struct {
	Tag        uint32 // must 1002
	Length     uint32 // total struct length not include Tag and Length
	IPVersion  uint32 // IP version 1-IPv4 ,2-IPv6 not support IPv6
	NextHop    net.IP // next hop ip address
	SrcMaskLen uint32 // source ip mask length
	DstMaskLen uint32 // Dst ip mask length
}

func decodeExtRouter(r io.ReadSeeker) (*SFExtRouterData, error) {
	var (
		er  = &SFExtRouterData{}
		err error
	)
	if err = read(r, &er.IPVersion); err != nil {
		return nil, err
	}
	buff := make([]byte, 4)
	if _, err = r.Read(buff); err != nil {
		return nil, err
	}
	er.NextHop = buff
	if err = read(r, &er.SrcMaskLen); err != nil {
		return nil, err
	}
	if err = read(r, &er.DstMaskLen); err != nil {
		return nil, err
	}
	return er, nil
}

// TransInfo get trans info
func (eh *SFExtRouterData) TransInfo(event common.MapStr) {
	event["nextHop"] = eh.NextHop
	event["srcmasklen"] = eh.SrcMaskLen
	event["dstmasklen"] = eh.DstMaskLen
}
