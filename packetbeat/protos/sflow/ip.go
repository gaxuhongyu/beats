package sflow

import (
	"io"
	"net"
)

// SFIPv4Data Ethernet header data
type SFIPv4Data struct {
	Tag         uint32 // must 3
	Length      uint32
	FrameLength uint32 // original data length,include layer3 header and data
	Protocol    uint32 // IP Protocol type ( TCP = 6, UDP = 17)
	SrcIP       net.IP // source ip
	DstIP       net.IP // dst ip
	SrcPort     uint32 //source port
	DstPort     uint32 // dst port
	TCPFlags    uint32 // only tcp protocol
	Tos         uint32 // IP type of service
}

func decodeSFIPv4Data(r io.ReadSeeker) (*SFIPv4Data, error) {
	var (
		ip  = &SFIPv4Data{}
		err error
	)
	if err = read(r, &ip.FrameLength); err != nil {
		return nil, err
	}
	if err = read(r, &ip.Protocol); err != nil {
		return nil, err
	}
	buff1 := make([]byte, 4)
	if _, err = r.Read(buff1); err != nil {
		return nil, err
	}
	ip.SrcIP = buff1
	buff2 := make([]byte, 4)
	if _, err = r.Read(buff2); err != nil {
		return nil, err
	}
	ip.DstIP = buff2
	if err = read(r, &ip.SrcPort); err != nil {
		return nil, err
	}
	if err = read(r, &ip.DstPort); err != nil {
		return nil, err
	}
	if err = read(r, &ip.TCPFlags); err != nil {
		return nil, err
	}
	if err = read(r, &ip.Tos); err != nil {
		return nil, err
	}
	return ip, nil
}
