package sflow

import (
	"errors"
	"fmt"
	"io"

	"github.com/elastic/beats/libbeat/common"
)

var (
	errShortEthHeaderLen = errors.New("ethernet header too short")
)

// SFEthernetHeder Ethernet header data
type SFEthernetHeder struct {
	Tag         uint32 // must 2
	Length      uint32
	FrameLength uint32 //  original data length,include layer2 header and data
	SrcMac      string //  src mac
	DstMac      string //  dst mac
	Header      []byte //  original data
}

func decodeEthernetHeder(r io.ReadSeeker, length uint32) (*SFEthernetHeder, error) {
	var (
		eh  = &SFEthernetHeder{}
		err error
	)

	if err = read(r, &eh.FrameLength); err != nil {
		return nil, err
	}
	temp := make([]byte, length-4)
	if _, err = r.Read(temp); err != nil {
		return nil, err
	}
	eh.Header = temp
	if err = eh.paserMacInfo(); err != nil {
		return nil, err
	}
	return eh, nil
}

func (eh *SFEthernetHeder) paserMacInfo() error {
	if len(eh.Header) < 14 {
		return errShortEthHeaderLen
	}
	b := eh.Header
	FmtAddr := "%0.2x:%0.2x:%0.2x:%0.2x:%0.2x:%0.2x"
	eh.SrcMac = fmt.Sprintf(FmtAddr, b[0], b[1], b[2], b[3], b[4], b[5])
	eh.DstMac = fmt.Sprintf(FmtAddr, b[6], b[7], b[8], b[9], b[10], b[11])
	return nil
}

// TransInfo get trans info
func (eh *SFEthernetHeder) TransInfo(event common.MapStr) {
	event["SrcMac"] = eh.SrcMac
	event["DstMac"] = eh.DstMac
}
