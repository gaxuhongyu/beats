package sflow

import (
	"io"

	"github.com/VerizonDigital/vflow/packet"
	"github.com/elastic/beats/libbeat/common"
)

// SFRawPacketHeader raw packet header data
type SFRawPacketHeader struct {
	Tag            uint32 // must 1
	Length         uint32
	HeaderProtocol uint32 // original data mac protocol type
	FrameLength    uint32 // original data length
	StrippedLength uint32 //  strip data length
	HeaderLength   uint32 // HeaderLength + StrippedLength = FrameLength
	data           []byte // original data
	header         *packet.Packet
}

func decodeRawPacketHeader(r io.ReadSeeker, length uint32) (*SFRawPacketHeader, error) {
	var (
		header = &SFRawPacketHeader{}
		err    error
	)
	if err = read(r, &header.HeaderProtocol); err != nil {
		return nil, err
	}
	if err = read(r, &header.FrameLength); err != nil {
		return nil, err
	}
	if err = read(r, &header.StrippedLength); err != nil {
		return nil, err
	}
	if err = read(r, &header.HeaderLength); err != nil {
		return nil, err
	}
	temp := make([]byte, length-16)
	if _, err = r.Read(temp); err != nil {
		return nil, err
	}
	header.data = temp
	head := packet.NewPacket()
	if header.header, err = head.Decoder(header.data); err != nil {
		return nil, err
	}
	return header, nil
}

// TransInfo get trans info
func (rp *SFRawPacketHeader) TransInfo(event common.MapStr) {
	event["PackageSize"] = rp.FrameLength
	event["VlanID"] = rp.header.L2.Vlan
	event["EtherType"] = rp.header.L2.EtherType
	switch rp.header.L3.(type) {
	case packet.IPv4Header:
		header := rp.header.L3.(*packet.IPv4Header)
		event["IPVersion"] = header.Version
		event["Tos"] = header.TOS
		event["Ttl"] = header.TTL
		event["IPProtocol"] = header.Protocol
		event["SrcIP"] = header.Src
		event["DstIP"] = header.Dst
	case packet.IPv6Header:
		header := rp.header.L3.(*packet.IPv6Header)
		event["IPVersion"] = header.Version
		event["IPProtocol"] = header.NextHeader
		event["SrcIP"] = header.Src
		event["DstIP"] = header.Dst
	}

	switch rp.header.L4.(type) {
	case packet.ICMP:
		header := rp.header.L4.(*packet.ICMP)
		event["IcmpType"] = header.Type
		event["IcmpCode"] = header.Code
	case packet.TCPHeader:
		header := rp.header.L4.(*packet.TCPHeader)
		event["SrcPort"] = header.SrcPort
		event["DstPort"] = header.DstPort
		event["TcpFlags"] = header.Flags
	case packet.UDPHeader:
		header := rp.header.L4.(*packet.UDPHeader)
		event["SrcPort"] = header.SrcPort
		event["DstPort"] = header.DstPort
	}
}
