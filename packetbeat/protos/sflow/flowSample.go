package sflow

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/VerizonDigital/vflow/packet"
	"github.com/elastic/beats/libbeat/common"
)

// SFSampleHeader Expanded Flow sample struct(http://www.sflow.org/developers/diagrams/sFlowV5Sample.pdf)
type SFSampleHeader struct {
	Tag        uint32 // must 1
	Length     uint32
	SequenceNo uint32 // Sequence of sFlow sample
	SourceID   uint32 // source id type 0=ifIndex|1=smonVlanDataSource|2=entPhysicalEntry
	SampleRate uint32 // sample rate
	SamplePool uint32 // sample pool packet total count
	Drops      uint32 // drop count
	Input      uint32 // SNMP ifIndex of input interface, 0 if not known
	Output     uint32 // SNMP ifIndex of output interface, 0 if not known
	SamplesNo  uint32 // Number of flow samples
}

// SFExpandedSampleHeader Expanded Flow sample struct
type SFExpandedSampleHeader struct {
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
	data           []byte // original data
	header         *packet.Packet
}

// SFEthernetHeder Ethernet header data
type SFEthernetHeder struct {
	Tag         uint32 // must 2
	Length      uint32
	FrameLength uint32 //  original data length,include layer2 header and data
	SrcMac      string //  src mac
	DstMac      string //  dst mac
	Header      []byte //  original data
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

// SFIPv6Data packet data ipv6
type SFIPv6Data struct {
	Tag         uint32 //must 4
	Length      uint32
	FrameLength uint32
	NextHeader  uint32 // ip next header (6=tcp|17=udp)
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint32 //source port
	DstPort     uint32 // dst port
	TCPFlags    uint32 // only tcp protocol
	Priority    uint32 // ip priority
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

const (
	// SFRawPacketFormat raw packet header format
	SFRawPacketFormat = uint32(1)
	// SFEthernetFormat ethernet frame header format
	SFEthernetFormat = uint32(2)
	// SFIPV4DataFormat ipv4 data format
	SFIPV4DataFormat = uint32(3)
	// SFIPV6DataFormat ipv6 data format
	SFIPV6DataFormat = uint32(4)
	// SFExtSwitchDataFormat extended vlan format
	SFExtSwitchDataFormat = uint32(1001)
	// SFExtRouterDataFormat extended router format
	SFExtRouterDataFormat = uint32(1002)
	// SFExtGatewayDataFormat extended data gateway+nexthop router ip
	SFExtGatewayDataFormat = uint32(1003)
	// SFExtUserDataFormat Extended User Data
	SFExtUserDataFormat = uint32(1004)
	// SFExtURLDataFormat Url Data extended url user+host
	SFExtURLDataFormat = uint32(1005)
	// SFExtMPLSDataFormat Extended MPLS Data
	SFExtMPLSDataFormat = uint32(1006)
	// SFExtNATDataFormat Extended NAT Data
	SFExtNATDataFormat = uint32(1007)
	// SFExtMPLSTunnelFormat Extended MPLS Tunnel
	SFExtMPLSTunnelFormat = uint32(1008)
	// SFExtMPLSVCFormat Extended MPLS VC
	SFExtMPLSVCFormat = uint32(1009)
	// SFExtMPLSSFECFormat Extended MPLS FEC
	SFExtMPLSSFECFormat = uint32(1010)
	// SFExtMPLSLVPFECFormat Extended MPLS LVP FEC
	SFExtMPLSLVPFECFormat = uint32(1011)
	// SFExtVlanTunnelFormat Extended VLAN tunnel
	SFExtVlanTunnelFormat = uint32(1012)
)

var (
	errShortEthHeaderLen = errors.New("ethernet header too short")
)

func flowSampleDecode(r io.ReadSeeker, length uint32) ([]SfTrans, error) {
	var (
		data         []SfTrans
		record       SfTrans
		sampleHeader *SFSampleHeader
		err          error
	)

	if sampleHeader, err = decodeSampleHeader(r); err != nil {
		return nil, err
	}
	sampleHeader.Tag = SFSampleTag
	sampleHeader.Length = length
	data = append(data, sampleHeader)
	for i := uint32(0); i < sampleHeader.SamplesNo; i++ {
		if record, err = decodeFlowRedord(r); err != nil {
			return nil, err
		}
		data = append(data, record)
	}
	return data, nil
}

func decodeSampleHeader(r io.ReadSeeker) (*SFSampleHeader, error) {
	var (
		sh  = &SFSampleHeader{}
		err error
	)
	if err = read(r, &sh.SequenceNo); err != nil {
		return nil, err
	}
	if err = read(r, &sh.SourceID); err != nil {
		return nil, err
	}
	if err = read(r, &sh.SampleRate); err != nil {
		return nil, err
	}
	if err = read(r, &sh.SamplePool); err != nil {
		return nil, err
	}
	if err = read(r, &sh.Drops); err != nil {
		return nil, err
	}
	if err = read(r, &sh.Input); err != nil {
		return nil, err
	}
	if err = read(r, &sh.Output); err != nil {
		return nil, err
	}
	if err = read(r, &sh.SamplesNo); err != nil {
		return nil, err
	}
	debugf("Unpack SFSampleHeader:%X", sh)
	return sh, nil
}

func decodeFlowRedord(r io.ReadSeeker) (SfTrans, error) {
	var result SfTrans
	tag, len, err := getSampleInfo(r)
	if err != nil {
		return nil, err
	}
	switch tag {
	case SFRawPacketFormat:
		var raw *SFRawPacketHeader
		if raw, err = decodeRawPacketHeader(r, len); err != nil {
			debugf("Read Raw data error:%s", err.Error())
			return nil, err
		}
		raw.Tag = tag
		raw.Length = len
		debugf("Unpack SFRawPacketHeader:%X", raw)
		result = raw
	case SFEthernetFormat:
		var eth *SFEthernetHeder
		if eth, err = decodeEthernetHeder(r, len); err != nil {
			return nil, err
		}
		eth.Tag = tag
		eth.Length = len
		debugf("Unpack SFEthernetHeder:%X", eth)
		result = eth
	case SFIPV4DataFormat:
		var ip *SFIPv4Data
		if ip, err = decodeSFIPv4Data(r); err != nil {
			return nil, err
		}
		ip.Tag = tag
		ip.Length = len
		debugf("Unpack SFIPv4Data:%X", ip)
		result = ip
	case SFIPV6DataFormat:
		var ip *SFIPv6Data
		if ip, err = decodeSFIPv6Data(r); err != nil {
			return nil, err
		}
		ip.Tag = tag
		ip.Length = len
		debugf("Unpack SFIPV6DataFormat:%X", ip)
		result = ip
	case SFExtRouterDataFormat:
		var er *SFExtRouterData
		if er, err = decodeExtRouter(r); err != nil {
			return nil, err
		}
		er.Tag = tag
		er.Length = len
		debugf("Unpack SFExtRouterData:%X", er)
		result = er
	case SFExtSwitchDataFormat:
		var es *SFExtSwitchData
		if es, err = decodeExtSwitch(r); err != nil {
			return nil, err
		}
		es.Tag = tag
		es.Length = len
		debugf("Unpack SFExtSwitchData:%X", es)
		result = es
	default:
		r.Seek(int64(len), 1)
		debugf("Not support tag :%d", tag)
	}
	return result, nil
}

// TransInfo get SFExpandedSampleHeader trans info
func (sh *SFSampleHeader) TransInfo(event common.MapStr) {
	event["sequenceno"] = sh.SamplesNo
	event["samplerate"] = sh.SampleRate
	event["samplepool"] = sh.SamplePool
	event["drops"] = sh.Drops
	event["inputindex"] = sh.Input
	event["outputindex"] = sh.Output
	event["flowsrecords"] = sh.SampleRate
}

func flowExpandedSampleDecode(r io.ReadSeeker, length uint32) ([]SfTrans, error) {
	var (
		data            []SfTrans
		record          SfTrans
		expSampleHeader *SFExpandedSampleHeader
		err             error
	)

	if expSampleHeader, err = decodeExpandedSampleHeader(r); err != nil {
		return nil, err
	}
	expSampleHeader.Tag = SFExtSampleTag
	expSampleHeader.Length = length
	data = append(data, expSampleHeader)
	for i := uint32(0); i < expSampleHeader.SamplesNo; i++ {
		if record, err = decodeFlowRedord(r); err != nil {
			return nil, err
		}
		data = append(data, record)
	}
	return data, err
}

func decodeExpandedSampleHeader(r io.ReadSeeker) (*SFExpandedSampleHeader, error) {
	var (
		sh  = &SFExpandedSampleHeader{}
		err error
	)
	if err = read(r, &sh.SequenceNo); err != nil {
		return nil, err
	}
	if err = read(r, &sh.DSClass); err != nil {
		return nil, err
	}
	if err = read(r, &sh.DSIndex); err != nil {
		return nil, err
	}
	if err = read(r, &sh.SampleRate); err != nil {
		return nil, err
	}
	if err = read(r, &sh.SamplePool); err != nil {
		return nil, err
	}
	if err = read(r, &sh.Drops); err != nil {
		return nil, err
	}
	if err = read(r, &sh.InputFormat); err != nil {
		return nil, err
	}
	if err = read(r, &sh.InputIndex); err != nil {
		return nil, err
	}
	if err = read(r, &sh.OutputFormat); err != nil {
		return nil, err
	}
	if err = read(r, &sh.OutputIndex); err != nil {
		return nil, err
	}
	if err = read(r, &sh.SamplesNo); err != nil {
		return nil, err
	}
	debugf("Unpack SFExpandedSampleHeader:%X", sh)
	return sh, nil
}

// TransInfo get SFExpandedSampleHeader trans info
func (sh *SFExpandedSampleHeader) TransInfo(event common.MapStr) {
	event["sequenceno"] = sh.SamplesNo
	event["samplerate"] = sh.SampleRate
	event["samplepool"] = sh.SamplePool
	event["drops"] = sh.Drops
	event["inputformat"] = sh.InputFormat
	event["inputindex"] = sh.InputIndex
	event["outputformat"] = sh.OutputFormat
	event["outputindex"] = sh.OutputIndex
	event["flowsrecords"] = sh.SampleRate
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

// TransInfo get SFRawPacketHeader trans info
func (rp *SFRawPacketHeader) TransInfo(event common.MapStr) {
	var proto int
	event["packagesize"] = rp.FrameLength
	event["vlanid"] = rp.header.L2.Vlan
	event["ethertype"] = rp.header.L2.EtherType
	switch rp.header.L2.EtherType {
	case packet.EtherTypeIPv4:
		header := rp.header.L3.(packet.IPv4Header)
		event["ipversion"] = header.Version
		event["tos"] = header.TOS
		event["ttl"] = header.TTL
		event["ipprotocol"] = header.Protocol
		event["srcip"] = header.Src
		event["dstip"] = header.Dst
		proto = header.Protocol
	case packet.EtherTypeIPv6:
		header := rp.header.L3.(packet.IPv6Header)
		event["ipversion"] = header.Version
		event["ipprotocol"] = header.NextHeader
		event["srcip"] = header.Src
		event["dstip"] = header.Dst
		proto = header.NextHeader
	}

	switch proto {
	case packet.IANAProtoICMP:
		header := rp.header.L4.(packet.ICMP)
		event["icmptype"] = header.Type
		event["icmpcode"] = header.Code
	case packet.IANAProtoTCP:
		header := rp.header.L4.(packet.TCPHeader)
		event["srcport"] = header.SrcPort
		event["dstport"] = header.DstPort
		event["tcpflags"] = header.Flags
	case packet.IANAProtoUDP:
		header := rp.header.L4.(packet.UDPHeader)
		event["srcport"] = header.SrcPort
		event["dstport"] = header.DstPort
	}
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

// TransInfo get SFEthernetHeder trans info
func (eh *SFEthernetHeder) TransInfo(event common.MapStr) {
	event["srcmac"] = eh.SrcMac
	event["dstmac"] = eh.DstMac
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

// TransInfo get SFIPv4Data trans info
func (eh *SFIPv4Data) TransInfo(event common.MapStr) {

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

// TransInfo get SFExtRouterData trans info
func (eh *SFExtRouterData) TransInfo(event common.MapStr) {
	event["nextHop"] = eh.NextHop
	event["srcmasklen"] = eh.SrcMaskLen
	event["dstmasklen"] = eh.DstMaskLen
}

func decodeExtSwitch(r io.ReadSeeker) (*SFExtSwitchData, error) {
	var (
		es  = &SFExtSwitchData{}
		err error
	)
	if err = read(r, &es.SrcVlanID); err != nil {
		return nil, err
	}
	if err = read(r, &es.SrcVlanPriority); err != nil {
		return nil, err
	}
	if err = read(r, &es.DstVlanID); err != nil {
		return nil, err
	}
	if err = read(r, &es.DstVlanPriority); err != nil {
		return nil, err
	}
	return es, nil
}

// TransInfo get SFExtSwitchData trans info
func (es *SFExtSwitchData) TransInfo(event common.MapStr) {
	event["srcvlanid"] = es.SrcVlanID
	event["dstvlanid"] = es.DstVlanID
}

func decodeSFIPv6Data(r io.ReadSeeker) (*SFIPv6Data, error) {
	var (
		v6  = &SFIPv6Data{}
		err error
	)
	if err = read(r, &v6.FrameLength); err != nil {
		return nil, err
	}
	if err = read(r, &v6.NextHeader); err != nil {
		return nil, err
	}
	buff1 := make([]byte, 16)
	if _, err = r.Read(buff1); err != nil {
		return nil, err
	}
	v6.SrcIP = buff1
	buff2 := make([]byte, 16)
	if _, err = r.Read(buff2); err != nil {
		return nil, err
	}
	v6.SrcIP = buff2
	if err = read(r, &v6.SrcPort); err != nil {
		return nil, err
	}
	if err = read(r, &v6.DstPort); err != nil {
		return nil, err
	}
	if err = read(r, &v6.TCPFlags); err != nil {
		return nil, err
	}
	if err = read(r, &v6.Priority); err != nil {
		return nil, err
	}
	return v6, nil
}

// TransInfo get ipv6 data trans info
func (eh *SFIPv6Data) TransInfo(event common.MapStr) {
	event["srcip"] = eh.SrcIP
	event["dstip"] = eh.DstIP
	event["srcport"] = eh.SrcPort
	event["dstport"] = eh.DstPort
	event["tcpflags"] = eh.TCPFlags
	event["ipprotocol"] = eh.NextHeader
}
