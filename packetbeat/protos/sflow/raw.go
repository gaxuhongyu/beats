package sflow

import (
	"io"

	"github.com/VerizonDigital/vflow/packet"
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
