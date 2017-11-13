package sflow

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// SFDecoder represents sFlow decoder
type SFDecoder struct {
	reader   io.ReadSeeker
	filter   []uint32 // Filter data format(s)
	datagram *SFDatagram
	data     []*SampleMessage
	ts       time.Time
}

// SFDatagram represents sFlow datagram
type SFDatagram struct {
	Version      uint32 // Datagram version
	IPVersion    uint32 // IP version
	AgentAddress net.IP // Agent IP address
	AgentSubID   uint32 // Identifies a source of sFlow data
	SequenceNo   uint32 // Sequence of sFlow Datagrams
	SysUpTime    uint32 // Current time (in milliseconds since device last booted
	SamplesNo    uint32 // Number of samples
}

// SFSampleHeader Expanded Flow sample struct
type SFSampleHeader struct {
	Tag          uint32 // must 3
	Length       uint32
	SequenceNo   uint32 // Sequence of sFlow sample
	DSClass      uint32 // data source type default 0
	DSIndex      uint32 // data source index
	SampleRate   uint32 // sample rate
	SamplePool   uint32 // sample pool packet total count
	Drops        uint32 // drop count
	InputFormat  uint32 // input port type defalut 0
	InputIndex   uint32 // input port index value
	OutputFormat uint32 // output port type defalut 0
	OutputIndex  uint32 // output port index value
	SamplesNo    uint32 // Number of flow samples
}

// SFRawPacketHeader raw packet header data
type SFRawPacketHeader struct {
	Tag            uint32 // must 1
	Length         uint32
	HeaderProtocol uint32 // original data mac protocol type
	FrameLength    uint32 // original data length
	StrippedLength uint32 //  strip data length
	HeaderLength   uint32 // HeaderLength + StrippedLength = FrameLength
	Header         []byte // original data
}

// SFEthernetHeder Ethernet header data
type SFEthernetHeder struct {
	Tag         uint32 // must 2
	Length      uint32
	FrameLength uint32   // original data length,include layer2 header and data
	SrcMac      [6]uint8 //  src mac
	DstMac      [6]uint8 //  src mac
	Header      []byte   // original data
}

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

// SFExtRouterData Extended router data
type SFExtRouterData struct {
	Tag        uint32 // must 1002
	Length     uint32 // total struct length not include Tag and Length
	IPVersion  uint32 // IP version 1-IPv4 ,2-IPv6 not support IPv6
	NextHop    net.IP // next hop ip address
	SrcMaskLen uint32 // source ip mask length
	DstMaskLen uint32 // Dst ip mask length
}

// SFExtSwitchData Extended Vlan priority data
type SFExtSwitchData struct {
	Tag             uint32 // must 1001
	Length          uint32 // total struct length not include Tag and Length
	SrcVlanID       uint32 // in vlan id
	SrcVlanPriority uint32 // in vlan priority
	DstVlanID       uint32 // out vlan id
	DstVlanPriority uint32 // out vlan priority
}

// SampleMessage represents flow sample decoded packet
type SampleMessage struct {
	Header            *SFSampleHeader
	RawPacketHeader   *SFRawPacketHeader
	EthernetFrameData *SFEthernetHeder
	IPv4Data          *SFIPv4Data
	ExtRouterData     *SFExtRouterData
	ExtSwitchData     *SFExtSwitchData
}

var (
	errDataLengthUnknown   = errors.New("the sflow data length is unknown")
	errSFVersionNotSupport = errors.New("the sflow version doesn't support")
)

const (
	// SFSampleTag flow sample tag
	SFSampleTag = uint32(3)
	// SFCounterTag Counter sample tag
	SFCounterTag = uint32(4)
	// SFRawPacketTag raw packet header tag
	SFRawPacketTag = uint32(1)
	// SFEthernetTag ethernet frame header tag
	SFEthernetTag = uint32(2)
	// SFIPV4Tag ipv4 header tag
	SFIPV4Tag = uint32(3)
	// SFExtRouterDataTag extended router tag
	SFExtRouterDataTag = uint32(1002)
	// SFExtSwitchDataTag extended vlan tag
	SFExtSwitchDataTag = uint32(1001)
)

// NewSFDecoder constructs new sflow decoder
func NewSFDecoder(r io.ReadSeeker, f []uint32) SFDecoder {
	return SFDecoder{
		reader: r,
		filter: f,
		ts:     time.Now(),
	}
}

// SFDecode decodes sFlow data
func (d *SFDecoder) SFDecode() ([]interface{}, error) {
	// var data []interface{}
	datagram, err := d.sfHeaderDecode()
	if err != nil {
		return nil, err
	}
	d.datagram = datagram

	for i := uint32(0); i < datagram.SamplesNo; i++ {
		sfTypeFormat, sfDataLength, err := getSampleInfo(d.reader)
		if err != nil {
			return nil, err
		}

		switch sfTypeFormat {
		case SFSampleTag:
			h, err := flowSampleDecode(d.reader, sfDataLength)
			if err != nil {
				debugf("flowSampleDecode Decode Error:%s", err.Error())
				return nil, err
			}
			d.data = append(d.data, h)
		case SFCounterTag:
			d.reader.Seek(int64(sfDataLength), 1)
		default:
			d.reader.Seek(int64(sfDataLength), 1)
		}

	}
	return nil, nil
}

func (d *SFDecoder) sfHeaderDecode() (*SFDatagram, error) {
	var (
		datagram = &SFDatagram{}
		ipLen    = 4
		err      error
	)

	if err = read(d.reader, &datagram.Version); err != nil {
		return nil, err
	}

	if datagram.Version != 5 {
		return nil, errSFVersionNotSupport
	}

	if err = read(d.reader, &datagram.IPVersion); err != nil {
		return nil, err
	}

	// read the agent ip address
	if datagram.IPVersion == 2 {
		ipLen = 16
	}
	buff := make([]byte, ipLen)
	if _, err = d.reader.Read(buff); err != nil {
		return nil, err
	}
	datagram.AgentAddress = buff

	if err = read(d.reader, &datagram.AgentSubID); err != nil {
		return nil, err
	}
	if err = read(d.reader, &datagram.SequenceNo); err != nil {
		return nil, err
	}
	if err = read(d.reader, &datagram.SysUpTime); err != nil {
		return nil, err
	}
	if err = read(d.reader, &datagram.SamplesNo); err != nil {
		return nil, err
	}
	debugf("Unpack SFDatagram:%X", datagram)
	return datagram, nil
}

func flowSampleDecode(r io.ReadSeeker, length uint32) (*SampleMessage, error) {
	var (
		sampleMessage   = &SampleMessage{}
		sampleHeader    = &SFSampleHeader{}
		rawPacketHeader = &SFRawPacketHeader{}
		ethernetHeder   = &SFEthernetHeder{}
		ipv4Data        = &SFIPv4Data{}
		extRouterData   = &SFExtRouterData{}
		extSwitchData   = &SFExtSwitchData{}
		err             error
	)

	if err = sampleHeader.decode(r); err != nil {
		return nil, err
	}
	sampleHeader.Tag = SFSampleTag
	sampleHeader.Length = length

	debugf("Unpack SFSampleHeader:%X", sampleHeader)
	for i := uint32(0); i < sampleHeader.SamplesNo; i++ {
		tag, len, err := getSampleInfo(r)
		if err != nil {
			return nil, err
		}
		switch tag {
		case SFRawPacketTag:
			rawPacketHeader.Tag = tag
			rawPacketHeader.Length = len
			if err = rawPacketHeader.decode(r); err != nil {
				debugf("Read Raw data error:%s", err.Error())
				return nil, err
			}
			debugf("Unpack SFRawPacketHeader:%X", rawPacketHeader)
		case SFEthernetTag:
			ethernetHeder.Tag = tag
			ethernetHeder.Length = len
			if err = ethernetHeder.decode(r); err != nil {
				return nil, err
			}
		case SFIPV4Tag:
			ipv4Data.Tag = tag
			ipv4Data.Length = len
			if err = ipv4Data.decode(r); err != nil {
				return nil, err
			}
		case SFExtRouterDataTag:
			extRouterData.Tag = tag
			extRouterData.Length = len
			if err = extRouterData.decode(r); err != nil {
				return nil, err
			}
		case SFExtSwitchDataTag:
			extSwitchData.Tag = tag
			extSwitchData.Length = len
			if err = extSwitchData.decode(r); err != nil {
				return nil, err
			}
		default:
			debugf("Not support tag :%d", tag)
		}
	}
	sampleMessage.Header = sampleHeader
	sampleMessage.RawPacketHeader = rawPacketHeader
	sampleMessage.EthernetFrameData = ethernetHeder
	sampleMessage.IPv4Data = ipv4Data
	sampleMessage.ExtRouterData = extRouterData
	sampleMessage.ExtSwitchData = extSwitchData
	return sampleMessage, err
}

func (sh *SFSampleHeader) decode(r io.ReadSeeker) error {
	var err error
	if err = read(r, &sh.SequenceNo); err != nil {
		return err
	}
	if err = read(r, &sh.DSClass); err != nil {
		return err
	}
	if err = read(r, &sh.DSIndex); err != nil {
		return err
	}
	if err = read(r, &sh.SampleRate); err != nil {
		return err
	}
	if err = read(r, &sh.SamplePool); err != nil {
		return err
	}
	if err = read(r, &sh.Drops); err != nil {
		return err
	}
	if err = read(r, &sh.InputFormat); err != nil {
		return err
	}
	if err = read(r, &sh.InputIndex); err != nil {
		return err
	}
	if err = read(r, &sh.OutputFormat); err != nil {
		return err
	}
	if err = read(r, &sh.OutputIndex); err != nil {
		return err
	}
	if err = read(r, &sh.SamplesNo); err != nil {
		return err
	}
	return nil
}

func (rp *SFRawPacketHeader) decode(r io.ReadSeeker) error {
	var err error
	if err = read(r, &rp.HeaderProtocol); err != nil {
		return err
	}
	if err = read(r, &rp.FrameLength); err != nil {
		return err
	}
	if err = read(r, &rp.StrippedLength); err != nil {
		return err
	}
	if err = read(r, &rp.HeaderLength); err != nil {
		return err
	}
	temp := make([]byte, rp.Length-16)
	if _, err = r.Read(temp); err != nil {
		return err
	}
	rp.Header = temp
	return nil
}

func (eh *SFEthernetHeder) decode(r io.ReadSeeker) error {
	var err error

	if err = read(r, &eh.FrameLength); err != nil {
		return err
	}
	temp := make([]byte, eh.Length-4)
	if _, err = r.Read(temp); err != nil {
		return err
	}
	eh.Header = temp
	debugf("Unpack SFEthernetHeder:%X", eh)
	return nil
}

func (ip *SFIPv4Data) decode(r io.ReadSeeker) error {
	var err error
	if err = read(r, &ip.FrameLength); err != nil {
		return err
	}
	if err = read(r, &ip.Protocol); err != nil {
		return err
	}
	buff1 := make([]byte, 4)
	if _, err = r.Read(buff1); err != nil {
		return err
	}
	ip.SrcIP = buff1
	buff2 := make([]byte, 4)
	if _, err = r.Read(buff2); err != nil {
		return err
	}
	ip.SrcIP = buff2
	if err = read(r, &ip.SrcPort); err != nil {
		return err
	}
	if err = read(r, &ip.DstPort); err != nil {
		return err
	}
	if err = read(r, &ip.TCPFlags); err != nil {
		return err
	}
	if err = read(r, &ip.Tos); err != nil {
		return err
	}
	debugf("Unpack SFIPv4Data:%X", ip)
	return nil
}

func (er *SFExtRouterData) decode(r io.ReadSeeker) error {
	var err error
	if err = read(r, &er.IPVersion); err != nil {
		return err
	}
	buff := make([]byte, 4)
	if _, err = r.Read(buff); err != nil {
		return err
	}
	er.NextHop = buff
	if err = read(r, &er.SrcMaskLen); err != nil {
		return err
	}
	if err = read(r, &er.DstMaskLen); err != nil {
		return err
	}
	debugf("Unpack SFExtRouterData:%X", er)
	return nil
}

func (es *SFExtSwitchData) decode(r io.ReadSeeker) error {
	var err error
	if err = read(r, &es.SrcVlanID); err != nil {
		return err
	}
	if err = read(r, &es.SrcVlanPriority); err != nil {
		return err
	}
	if err = read(r, &es.DstVlanID); err != nil {
		return err
	}
	if err = read(r, &es.DstVlanPriority); err != nil {
		return err
	}
	debugf("Unpack SFExtSwitchData:%X", es)
	return nil
}

func getSampleInfo(r io.ReadSeeker) (uint32, uint32, error) {
	var (
		sfTypeFormat uint32
		sfDataLength uint32
		err          error
	)

	if err = read(r, &sfTypeFormat); err != nil {
		return 0, 0, err
	}

	if err = read(r, &sfDataLength); err != nil {
		return 0, 0, errDataLengthUnknown
	}
	debugf("Tag:%d,Length:%d", sfTypeFormat, sfDataLength)
	return sfTypeFormat, sfDataLength, nil
}

func read(r io.Reader, v interface{}) error {
	return binary.Read(r, binary.BigEndian, v)
}
