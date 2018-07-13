package v5

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/elastic/beats/libbeat/common"
)

const (
	// Version Netflow v9 Packet Header is must 0x0009
	Version uint16 = 0x0005
)

// PacketHeader more detail see http://netflow.caligare.com/netflow_v5.htm
type PacketHeader struct {
	Version          uint16
	Count            uint16
	SysUpTime        uint32
	UnixSecs         uint32
	UnixNSecs        uint32
	FlowSequence     uint32
	EngineType       uint8
	EngineID         uint8
	SamplingInterval uint16
}

// Flow Data Flow Set See http://netflow.caligare.com/netflow_v5.htm
type Flow struct {
	SrcAddr     []byte
	DstAddr     []byte
	NextHop     []byte
	InputIndex  uint16
	OutPutIndex uint16
	Packets     uint32
	FrameLength uint32
	First       uint32
	Last        uint32
	SrcPort     uint16
	DstPort     uint16
	Padding1    uint8
	TCPFlags    uint8
	Protocol    uint8
	Tos         uint8
	SrcAs       uint16
	DstAs       uint16
	SrcMask     uint8
	DstMask     uint8
	Padding2    uint16
}

// Packet netflow v5 packet
type Packet struct {
	t      time.Time
	Header PacketHeader
	Flows  []*Flow
}

// Unmarshal Unmarshal PacketHeader
func (ph *PacketHeader) Unmarshal(r io.ReadSeeker) error {
	if err := read(r, &ph.Version); err != nil {
		return err
	}
	if err := read(r, &ph.Count); err != nil {
		return err
	}
	if err := read(r, &ph.SysUpTime); err != nil {
		return err
	}
	if err := read(r, &ph.UnixSecs); err != nil {
		return err
	}
	if err := read(r, &ph.UnixNSecs); err != nil {
		return err
	}
	if err := read(r, &ph.FlowSequence); err != nil {
		return err
	}
	if err := read(r, &ph.EngineType); err != nil {
		return err
	}
	if err := read(r, &ph.EngineID); err != nil {
		return err
	}
	if err := read(r, &ph.SamplingInterval); err != nil {
		return err
	}
	return nil
}

// Unmarshal Data Flow Set Unmarshal
func (f *Flow) Unmarshal(r io.ReadSeeker) error {
	debugf("----Data : %X", r)
	buff := make([]byte, 4)
	if _, err := r.Read(buff); err != nil {
		return err
	}
	f.SrcAddr = buff
	buff1 := make([]byte, 4)
	if _, err := r.Read(buff1); err != nil {
		return err
	}
	f.DstAddr = buff1
	buff2 := make([]byte, 4)
	if _, err := r.Read(buff2); err != nil {
		return err
	}
	f.NextHop = buff2
	if err := read(r, &f.InputIndex); err != nil {
		return err
	}
	if err := read(r, &f.OutPutIndex); err != nil {
		return err
	}
	if err := read(r, &f.Packets); err != nil {
		return err
	}
	if err := read(r, &f.FrameLength); err != nil {
		return err
	}
	if err := read(r, &f.First); err != nil {
		return err
	}
	if err := read(r, &f.Last); err != nil {
		return err
	}
	if err := read(r, &f.SrcPort); err != nil {
		return err
	}
	if err := read(r, &f.DstPort); err != nil {
		return err
	}
	if err := read(r, &f.Padding1); err != nil {
		return err
	}
	if err := read(r, &f.TCPFlags); err != nil {
		return err
	}
	if err := read(r, &f.Protocol); err != nil {
		return err
	}
	if err := read(r, &f.Tos); err != nil {
		return err
	}
	if err := read(r, &f.SrcAs); err != nil {
		return err
	}
	if err := read(r, &f.DstAs); err != nil {
		return err
	}
	if err := read(r, &f.SrcMask); err != nil {
		return err
	}
	if err := read(r, &f.DstMask); err != nil {
		return err
	}
	if err := read(r, &f.Padding2); err != nil {
		return err
	}
	return nil
}

// TransInfo Netflow v5 TransInfo
func (f *Flow) TransInfo(event common.MapStr) {
	event["src_ip"] = net.IPv4(f.SrcAddr[0], f.SrcAddr[1], f.SrcAddr[2], f.SrcAddr[3])
	event["dst_ip"] = net.IPv4(f.DstAddr[0], f.DstAddr[1], f.DstAddr[2], f.DstAddr[3])
	event["next_hop"] = net.IPv4(f.NextHop[0], f.NextHop[1], f.NextHop[2], f.NextHop[3])
	event["input_interface_value"] = f.InputIndex
	event["output_interface_value"] = f.OutPutIndex
	event["packets"] = f.Packets
	event["bytes"] = f.FrameLength
	event["first_switched"] = f.First
	event["last_switched"] = f.Last
	event["src_port"] = f.SrcPort
	event["dst_port"] = f.DstPort
	event["tcp_flags"] = f.TCPFlags
	event["ip_protocol"] = f.Protocol
	event["tos"] = f.Tos
	event["src_as"] = f.SrcAs
	event["dst_as"] = f.DstAs
	event["src_mask"] = f.SrcMask
	event["dst_mask"] = f.DstMask
}

func read(r io.Reader, v interface{}) error {
	return binary.Read(r, binary.BigEndian, v)
}
