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
	Tag           uint32 // must 1
	Length        uint32
	SequenceNo    uint32 // Sequence of sFlow sample
	SourceIDType  uint32 // source id type 0=ifIndex|1=smonVlanDataSource|2=entPhysicalEntry
	SourceIDIndex uint32 // source id index value
	SampleRate    uint32 // sample rate
	SamplePool    uint32 // sample pool packet total count
	Drops         uint32 // drop count
	Input         uint32 // SNMP ifIndex of input interface, 0 if not known
	Output        uint32 // SNMP ifIndex of output interface, 0 if not known
	SamplesNo     uint32 // Number of flow samples
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

// SFExtSwitchData Extended Vlan priority data
type SFExtSwitchData struct {
	Tag             uint32 // must 1001
	Length          uint32 // total struct length not include Tag and Length
	SrcVlanID       uint32 // in vlan id
	SrcVlanPriority uint32 // in vlan priority
	DstVlanID       uint32 // out vlan id
	DstVlanPriority uint32 // out vlan priority
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

// SFGatewayAsPath ext gateway as path
type SFGatewayAsPath struct {
	PathType uint32   // path segment type (1=set/unordered|2=sequence/ordered)
	Length   uint32   // length of as list
	AsNumber []uint32 // as number
}

// SFExtGatewayData Extended router data
type SFExtGatewayData struct {
	Tag            uint32             // must 1003
	Length         uint32             // total struct length not include Tag and Length
	IPVersion      uint32             // IP version 1-IPv4 ,2-IPv6 not support IPv6
	NextHop        net.IP             // next hop ip address v4=4byte|v6=16byte
	AsRouterNo     uint32             // as number of router
	AsSourceNo     uint32             // as number of source
	AsSourceNoPeer uint32             // as number of source peer
	DsetPathNo     uint32             // dest as paths no
	AsPath         []*SFGatewayAsPath // as path
	LenCommunities uint32             // length communities list
	communities    []uint32           // n * int communities
	LocalPref      uint32             // LocalPref
}

// SFExtUserData extended data user+charset
type SFExtUserData struct {
	Tag           uint32 // must 1004
	Length        uint32 // total struct length not include Tag and Length
	SourceCharset uint32 // source charset
	LenSourceUser uint32 // length source user string
	SourceUser    []byte // string source user
	DestCharset   uint32 // destination charset
	LenDestUser   uint32 // length destination user string
	DestUser      []byte // string destination user
}

// SFExtURLData extended url user+host
type SFExtURLData struct {
	Tag        uint32 // must 1005
	Length     uint32 // total struct length not include Tag and Length
	Direction  uint32 // 1=src|2=dest
	LengthURL  uint32 // URL length
	URLString  []byte // URL data
	LengthHost uint32 // host length
	HostString []byte // host data
}

// SFExtMPLSData Extended MPLS Data
type SFExtMPLSData struct {
	Tag           uint32 // must 1006
	Length        uint32 // total struct length not include Tag and Length
	IPVersion     uint32 // IP version of next hop router (1=v4|2=v6)
	NextHop       net.IP // IP address next hop router (v4=4byte|v6=16byte)
	InLabelCount  uint32 // n in label stack count
	InLabel       []byte // n in label stack data
	OutLabelCount uint32 // Out label stack count
	OutLabel      []byte // out label stack data
}

// SFExtNATData Extended MPLS Data
type SFExtNATData struct {
	Tag             uint32 // must 1007
	Length          uint32 // total struct length not include Tag and Length
	SourceIPVersion uint32 // IP version of source address (1=v4|2=v6)
	SourceIPAddr    net.IP // IP address source address (v4=4byte|v6=16byte)
	DestIPVersion   uint32 // IP version of destination address (1=v4|2=v6)
	DestIPAddr      net.IP // IP address destination address (v4=4byte|v6=16byte)
}

// SFExtMPLSTunnel Extended MPLS Tunnel
type SFExtMPLSTunnel struct {
	Tag           uint32 // must 1008
	Length        uint32 // total struct length not include Tag and Length
	TunnelNameLen uint32 // tunnel name length
	TunnelName    []byte // tunnel name
	TunnelID      uint32 // tunnel id
	TunnelCos     uint32 // tunnel cos value
}

// SFExtMPLSVC Extended MPLS VC
type SFExtMPLSVC struct {
	Tag               uint32 // must 1009
	Length            uint32 // total struct length not include Tag and Length
	VcInstanceNameLen uint32 // length vc instance name
	VcInstanceName    []byte // string vc instance name
	VcID              uint32 // int vll/vc id
	VcLabelCos        uint32 // tunnel cos value
}

// SFExtMPLSFEC Extended MPLS FEC
type SFExtMPLSFEC struct {
	Tag             uint32 // must 1010
	Length          uint32 // total struct length not include Tag and Length
	MplsFTNDescrLen uint32 // mplsFTNDescr length
	MplsFTNDescr    []byte // mplsFTNDescr
	MplsFTNMask     uint32 // mplsFTNMask
}

// SFExtMPLSLvpFec Extended MPLS FEC
type SFExtMPLSLvpFec struct {
	Tag                     uint32 // must 1011
	Length                  uint32 // total struct length not include Tag and Length
	MplsFecAddrPrefixLength uint32 // mplsFecAddrPrefixLength
}

// SFExtVlanTunnel Extended MPLS FEC
type SFExtVlanTunnel struct {
	Tag       uint32   // must 1012
	Length    uint32   // total struct length not include Tag and Length
	LayerLen  uint32   // n layer stack
	LayerData []uint32 // layer
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
		if record, err = decodeFlowRecord(r); err != nil {
			return nil, err
		}
		data = append(data, record)
	}
	return data, nil
}

func decodeSampleHeader(r io.ReadSeeker) (*SFSampleHeader, error) {
	var (
		sh   = &SFSampleHeader{}
		temp uint32
		err  error
	)
	if err = read(r, &sh.SequenceNo); err != nil {
		return nil, err
	}
	if err = read(r, &temp); err != nil {
		return nil, err
	}
	sh.SourceIDType = temp >> 24
	sh.SourceIDIndex = temp & 0x0FFF
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

func decodeFlowRecord(r io.ReadSeeker) (SfTrans, error) {
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
	case SFExtSwitchDataFormat:
		var es *SFExtSwitchData
		if es, err = decodeExtSwitch(r); err != nil {
			return nil, err
		}
		es.Tag = tag
		es.Length = len
		debugf("Unpack SFExtSwitchData:%X", es)
		result = es
	case SFExtRouterDataFormat:
		var er *SFExtRouterData
		if er, err = decodeExtRouter(r); err != nil {
			return nil, err
		}
		er.Tag = tag
		er.Length = len
		debugf("Unpack SFExtRouterData:%X", er)
		result = er
	case SFExtGatewayDataFormat:
		var gw *SFExtGatewayData
		if gw, err = decodeSFExtGatewayData(r); err != nil {
			return nil, err
		}
		gw.Tag = tag
		gw.Length = len
		debugf("Unpack SFExtGatewayData:%X", gw)
		result = gw
	case SFExtUserDataFormat:
		var user *SFExtUserData
		if user, err = decodeSFExtUserData(r); err != nil {
			return nil, err
		}
		user.Tag = tag
		user.Length = len
		debugf("Unpack SFExtUserData:%X", user)
		result = user
	case SFExtURLDataFormat:
		var url *SFExtURLData
		if url, err = decodeSFExtURLData(r); err != nil {
			return nil, err
		}
		url.Tag = tag
		url.Length = len
		debugf("Unpack SFExtURLData:%X", url)
		result = url
	case SFExtMPLSDataFormat:
		var mpls *SFExtMPLSData
		if mpls, err = decodeSFExtMPLSData(r); err != nil {
			return nil, err
		}
		mpls.Tag = tag
		mpls.Length = len
		debugf("Unpack SFExtMPLSData:%X", mpls)
		result = mpls
	case SFExtNATDataFormat:
		var nat *SFExtNATData
		if nat, err = decodeSFExtNATData(r); err != nil {
			return nil, err
		}
		nat.Tag = tag
		nat.Length = len
		debugf("Unpack SFExtNATData:%X", nat)
		result = nat
	case SFExtMPLSTunnelFormat:
		var tunnel *SFExtMPLSTunnel
		if tunnel, err = decodeSFExtMPLSTunnel(r); err != nil {
			return nil, err
		}
		tunnel.Tag = tag
		tunnel.Length = len
		debugf("Unpack SFExtMPLSTunnel:%X", tunnel)
		result = tunnel
	case SFExtMPLSVCFormat:
		var vc *SFExtMPLSVC
		if vc, err = decodeSFExtMPLSVC(r); err != nil {
			return nil, err
		}
		vc.Tag = tag
		vc.Length = len
		debugf("Unpack SFExtMPLSVC:%X", vc)
		result = vc
	case SFExtMPLSSFECFormat:
		var fec *SFExtMPLSFEC
		if fec, err = decodeSFExtMPLSFEC(r); err != nil {
			return nil, err
		}
		fec.Tag = tag
		fec.Length = len
		debugf("Unpack SFExtMPLSFEC:%X", fec)
		result = fec
	case SFExtMPLSLVPFECFormat:
		var lvp *SFExtMPLSLvpFec
		if lvp, err = decodeSFExtMPLSLvpFec(r); err != nil {
			return nil, err
		}
		lvp.Tag = tag
		lvp.Length = len
		debugf("Unpack SFExtMPLSFEC:%X", lvp)
		result = lvp
	case SFExtVlanTunnelFormat:
		var vlan *SFExtVlanTunnel
		if vlan, err = decodeSFExtVlanTunnel(r); err != nil {
			return nil, err
		}
		vlan.Tag = tag
		vlan.Length = len
		debugf("Unpack SFExtVlanTunnel:%X", vlan)
		result = vlan
	default:
		r.Seek(int64(len), 1)
		debugf("Not support tag :%d", tag)
	}
	return result, nil
}

// TransInfo get SFSampleHeader trans info
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
		if record, err = decodeFlowRecord(r); err != nil {
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

func decodeSFExtGatewayData(r io.ReadSeeker) (*SFExtGatewayData, error) {
	var (
		gw  = &SFExtGatewayData{}
		len uint32
		err error
	)
	if err = read(r, &gw.IPVersion); err != nil {
		return nil, err
	}
	if gw.IPVersion == 1 {
		len = 4
	} else if gw.IPVersion == 2 {
		len = 16
	}
	buff := make([]byte, len)
	if _, err = r.Read(buff); err != nil {
		return nil, err
	}
	gw.NextHop = buff
	if err = read(r, &gw.AsRouterNo); err != nil {
		return nil, err
	}
	if err = read(r, &gw.AsSourceNo); err != nil {
		return nil, err
	}
	if err = read(r, &gw.AsSourceNoPeer); err != nil {
		return nil, err
	}
	if err = read(r, &gw.DsetPathNo); err != nil {
		return nil, err
	}
	for index := uint32(0); index < gw.DsetPathNo; index++ {
		ap, e := decodeAsPath(r)
		if e != nil {
			return nil, e
		}
		gw.AsPath = append(gw.AsPath, ap)
	}
	if err = read(r, &gw.LenCommunities); err != nil {
		return nil, err
	}
	for index := uint32(0); index < gw.LenCommunities; index++ {
		var temp uint32
		if err = read(r, &temp); err != nil {
			return nil, err
		}
		gw.communities = append(gw.communities, temp)
	}
	if err = read(r, &gw.LocalPref); err != nil {
		return nil, err
	}
	return gw, nil
}

func decodeAsPath(r io.ReadSeeker) (*SFGatewayAsPath, error) {
	var (
		ap  = &SFGatewayAsPath{}
		err error
	)
	if err = read(r, &ap.PathType); err != nil {
		return nil, err
	}
	if err = read(r, &ap.Length); err != nil {
		return nil, err
	}
	for index := uint32(0); index < ap.Length; index++ {
		var temp uint32
		if err = read(r, &temp); err != nil {
			return nil, err
		}
		ap.AsNumber = append(ap.AsNumber, temp)
	}
	return ap, nil
}

// TransInfo get SFExtGatewayData data trans info
func (gw *SFExtGatewayData) TransInfo(event common.MapStr) {
	// event["srcip"] = eh.SrcIP
	// event["dstip"] = eh.DstIP
	// event["srcport"] = eh.SrcPort
	// event["dstport"] = eh.DstPort
	// event["tcpflags"] = eh.TCPFlags
	// event["ipprotocol"] = eh.NextHeader
}

func decodeSFExtUserData(r io.ReadSeeker) (*SFExtUserData, error) {
	var (
		eu  = &SFExtUserData{}
		err error
	)
	if err = read(r, &eu.SourceCharset); err != nil {
		return nil, err
	}
	if err = read(r, &eu.LenDestUser); err != nil {
		return nil, err
	}
	buff1 := make([]byte, eu.LenDestUser)
	if _, err = r.Read(buff1); err != nil {
		return nil, err
	}
	eu.SourceUser = buff1
	if err = read(r, &eu.DestCharset); err != nil {
		return nil, err
	}
	if err = read(r, &eu.LenDestUser); err != nil {
		return nil, err
	}
	buff2 := make([]byte, eu.LenDestUser)
	if _, err = r.Read(buff2); err != nil {
		return nil, err
	}
	eu.DestUser = buff2
	return eu, nil
}

// TransInfo get SFExtUserData data trans info
func (gw *SFExtUserData) TransInfo(event common.MapStr) {
	// event["srcip"] = eh.SrcIP
	// event["dstip"] = eh.DstIP
	// event["srcport"] = eh.SrcPort
	// event["dstport"] = eh.DstPort
	// event["tcpflags"] = eh.TCPFlags
	// event["ipprotocol"] = eh.NextHeader
}

func decodeSFExtURLData(r io.ReadSeeker) (*SFExtURLData, error) {
	var (
		url = &SFExtURLData{}
		err error
	)
	if err = read(r, &url.Direction); err != nil {
		return nil, err
	}
	if err = read(r, &url.LengthURL); err != nil {
		return nil, err
	}
	buff1 := make([]byte, url.LengthURL)
	if _, err = r.Read(buff1); err != nil {
		return nil, err
	}
	url.URLString = buff1
	if err = read(r, &url.LengthHost); err != nil {
		return nil, err
	}
	buff2 := make([]byte, url.LengthHost)
	if _, err = r.Read(buff2); err != nil {
		return nil, err
	}
	url.HostString = buff2
	return url, nil
}

// TransInfo get SFExtURLData data trans info
func (gw *SFExtURLData) TransInfo(event common.MapStr) {

}

func decodeSFExtMPLSData(r io.ReadSeeker) (*SFExtMPLSData, error) {
	var (
		mpls = &SFExtMPLSData{}
		len  = 4
		err  error
	)
	if err = read(r, &mpls.IPVersion); err != nil {
		return nil, err
	}
	if mpls.IPVersion == 2 {
		len = 16
	}
	buff := make([]byte, len)
	if _, err = r.Read(buff); err != nil {
		return nil, err
	}
	mpls.NextHop = buff
	if err = read(r, &mpls.InLabelCount); err != nil {
		return nil, err
	}
	buff1 := make([]byte, mpls.InLabelCount)
	if _, err = r.Read(buff1); err != nil {
		return nil, err
	}
	mpls.InLabel = buff1
	if err = read(r, &mpls.OutLabelCount); err != nil {
		return nil, err
	}
	buff2 := make([]byte, mpls.OutLabelCount)
	if _, err = r.Read(buff2); err != nil {
		return nil, err
	}
	mpls.OutLabel = buff2
	return mpls, nil
}

// TransInfo get SFExtMPLSData data trans info
func (gw *SFExtMPLSData) TransInfo(event common.MapStr) {

}

func decodeSFExtNATData(r io.ReadSeeker) (*SFExtNATData, error) {
	var (
		nat = &SFExtNATData{}
		len = 4
		err error
	)
	if err = read(r, &nat.SourceIPVersion); err != nil {
		return nil, err
	}
	if nat.SourceIPVersion == 2 {
		len = 16
	}
	buff := make([]byte, len)
	if _, err = r.Read(buff); err != nil {
		return nil, err
	}
	nat.SourceIPAddr = buff
	if err = read(r, &nat.DestIPVersion); err != nil {
		return nil, err
	}
	if nat.DestIPVersion == 1 {
		len = 4
	} else if nat.DestIPVersion == 2 {
		len = 16
	}
	buff1 := make([]byte, len)
	if _, err = r.Read(buff1); err != nil {
		return nil, err
	}
	nat.DestIPAddr = buff
	return nat, nil
}

// TransInfo get SFExtNATData data trans info
func (gw *SFExtNATData) TransInfo(event common.MapStr) {

}

func decodeSFExtMPLSTunnel(r io.ReadSeeker) (*SFExtMPLSTunnel, error) {
	var (
		tunnel = &SFExtMPLSTunnel{}
		err    error
	)
	if err = read(r, &tunnel.TunnelNameLen); err != nil {
		return nil, err
	}
	buff := make([]byte, tunnel.TunnelNameLen)
	if _, err = r.Read(buff); err != nil {
		return nil, err
	}
	tunnel.TunnelName = buff
	if err = read(r, &tunnel.TunnelID); err != nil {
		return nil, err
	}
	if err = read(r, &tunnel.TunnelCos); err != nil {
		return nil, err
	}
	return tunnel, nil
}

// TransInfo get SFExtMPLSTunnel data trans info
func (gw *SFExtMPLSTunnel) TransInfo(event common.MapStr) {

}

func decodeSFExtMPLSVC(r io.ReadSeeker) (*SFExtMPLSVC, error) {
	var (
		vc  = &SFExtMPLSVC{}
		err error
	)
	if err = read(r, &vc.VcInstanceNameLen); err != nil {
		return nil, err
	}
	buff := make([]byte, vc.VcInstanceNameLen)
	if _, err = r.Read(buff); err != nil {
		return nil, err
	}
	vc.VcInstanceName = buff
	if err = read(r, &vc.VcID); err != nil {
		return nil, err
	}
	if err = read(r, &vc.VcLabelCos); err != nil {
		return nil, err
	}
	return vc, nil
}

// TransInfo get SFExtMPLSVC data trans info
func (vc *SFExtMPLSVC) TransInfo(event common.MapStr) {

}

func decodeSFExtMPLSFEC(r io.ReadSeeker) (*SFExtMPLSFEC, error) {
	var (
		fec = &SFExtMPLSFEC{}
		err error
	)
	if err = read(r, &fec.MplsFTNDescrLen); err != nil {
		return nil, err
	}
	buff := make([]byte, fec.MplsFTNDescrLen)
	if _, err = r.Read(buff); err != nil {
		return nil, err
	}
	fec.MplsFTNDescr = buff
	if err = read(r, &fec.MplsFTNMask); err != nil {
		return nil, err
	}
	return fec, nil
}

// TransInfo get SFExtMPLSFEC data trans info
func (vc *SFExtMPLSFEC) TransInfo(event common.MapStr) {

}

func decodeSFExtMPLSLvpFec(r io.ReadSeeker) (*SFExtMPLSLvpFec, error) {
	var (
		lvp = &SFExtMPLSLvpFec{}
		err error
	)
	if err = read(r, &lvp.MplsFecAddrPrefixLength); err != nil {
		return nil, err
	}
	return lvp, nil
}

// TransInfo get SFExtMPLSLvpFec data trans info
func (vc *SFExtMPLSLvpFec) TransInfo(event common.MapStr) {

}

func decodeSFExtVlanTunnel(r io.ReadSeeker) (*SFExtVlanTunnel, error) {
	var (
		layer = &SFExtVlanTunnel{}
		err   error
	)
	if err = read(r, &layer.LayerLen); err != nil {
		return nil, err
	}
	for index := uint32(0); index < layer.LayerLen; index++ {
		var temp uint32
		if err = read(r, &temp); err != nil {
			return nil, err
		}
		layer.LayerData = append(layer.LayerData, temp)
	}
	return layer, nil
}

// TransInfo get SFExtVlanTunnel data trans info
func (vc *SFExtVlanTunnel) TransInfo(event common.MapStr) {

}
