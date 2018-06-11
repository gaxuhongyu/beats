package v9

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// TemplateInfo save Template data
var filedsInfo map[string]*filed

var fileds = [][3]string{
	{"1", "frame_length", "uint64"},
	// {"2", "IN_PKTS", "uint64"},
	// {"3", "FLOWS", "uint32"},
	{"4", "ip_protocol", "uint8"},
	{"5", "tos", "uint8"},
	{"6", "tcp_flags", "uint8"},
	{"7", "src_port", "uint16"},
	{"8", "src_ip", "ip"},
	// {"9", "SRC_MASK", "uint8"},
	{"10", "input_interface_value", "uint32"},
	{"11", "dst_port", "uint16"},
	{"12", "dst_ip", "ip"},
	// {"13", "DST_MASK", "uint8"},
	{"14", "output_interface_value", "uint32"},
	// {"15", "IPV4_NEXT_HOP", "ip"},
	// {"16", "SRC_AS", "uint16"},
	// {"17", "DST_AS", "uint16"},
	// {"18", "BGP_IPV4_NEXT_HOP", "ip"},
	// {"19", "MUL_DST_PKTS", "uint32"},
	// {"20", "MUL_DST_BYTES", "uint32"},
	// {"21", "LAST_SWITCHED", "time"},
	// {"22", "FIRST_SWITCHED", "time"},
	{"23", "frame_length", "uint64"},
	// {"24", "OUT_PKTS", "uint64"},
	// {"27", "IPV6_SRC_ADDR", "ip"},
	// {"28", "IPV6_DST_ADDR", "ip"},
	// {"29", "IPV6_SRC_MASK", "uint8"},
	// {"30", "IPV6_DST_MASK", "uint8"},
	// {"31", "IPV6_FLOW_LABEL", "uint32"},
	// {"32", "ICMP_TYPE", "uint16"},
	// {"33", "MUL_IGMP_TYPE", "uint8"},
	// {"34", "SAMPLING_INTERVAL", "uint32"},
	// {"35", "SAMPLING_ALGORITHM", "uint8"},
	// {"36", "FLOW_ACTIVE_TIMEOUT", "uint16"},
	// {"37", "FLOW_INACTIVE_TIMEOUT", "uint16"},
	// {"38", "ENGINE_TYPE", "uint8"},
	// {"39", "ENGINE_ID", "uint8"},
	// {"40", "TOTAL_BYTES_EXP", "uint32"},
	// {"41", "TOTAL_PKTS_EXP", "uint32"},
	// {"42", "TOTAL_FLOWS_EXP", "uint32"},
	// {"46", "MPLS_TOP_LABEL_TYPE", "uint8"},
	// {"47", "MPLS_TOP_LABEL_IP_ADDR", "uint32"},
	// {"48", "FLOW_SAMPLER_ID", "uint8"},
	// {"49", "FLOW_SAMPLER_MODE", "uint8"},
	// {"50", "FLOW_SAMPLER_RANDOM_INTERVAL", "uint32"},
	// {"55", "DST_TOS", "uint8"},
	// {"56", "SRC_MAC", "mac"},
	// {"57", "DST_MAC", "mac"},
	// {"58", "SRC_VLAN", "uint16"},
	// {"59", "DST_VLAN", "uint16"},
	{"60", "ip_version", "uint8"},
	// {"61", "DIRECTION", "uint8"},
	// {"62", "IPV6_NEXT_HOP", "ip"},
	// {"63", "BGP_IPV6_NEXT_HOP", "ip"},
	// {"64", "IPV6_OPTION_HEADERS", "uint32"},
	// {"70", "MPLS_LABEL_1", "uint32"},
	// {"71", "MPLS_LABEL_2", "uint32"},
	// {"72", "MPLS_LABEL_3", "uint32"},
	// {"73", "MPLS_LABEL_4", "uint32"},
	// {"74", "MPLS_LABEL_5", "uint32"},
	// {"75", "MPLS_LABEL_6", "uint32"},
	// {"76", "MPLS_LABEL_7", "uint32"},
	// {"77", "MPLS_LABEL_8", "uint32"},
	// {"78", "MPLS_LABEL_9", "uint32"},
	// {"79", "MPLS_LABEL_10", "uint32"},
}

// Filed filed type define
type filed struct {
	Name string
	Type string
}

// Value dff
func (f *filed) Value(d []byte) interface{} {
	switch f.Type {
	case "uint8":
		return uint8(d[0])
	case "uint16":
		return binary.BigEndian.Uint16(d[0:])
	case "uint32":
		return binary.BigEndian.Uint32(d[0:])
	case "uint64":
		return binary.BigEndian.Uint64(d[0:])
	case "mac":
		FmtMacAddr := "%0.2x:%0.2x:%0.2x:%0.2x:%0.2x:%0.2x"
		return fmt.Sprintf(FmtMacAddr, d[0], d[1], d[2], d[3], d[4], d[5])
	case "ip":
		var ip net.IP
		if len(d) > 4 {
			ip = net.IPv4(d[0], d[1], d[2], d[3])
		} else {
			ip = net.IP(d)
		}
		return ip
	case "time":
		s := binary.BigEndian.Uint32(d[0:])
		return time.Unix(int64(s/1000), 0)
	}
	return nil
}

func init() {
	filedsInfo = make(map[string]*filed)
	for _, v := range fileds {
		f := &filed{Name: v[1], Type: v[2]}
		filedsInfo[v[0]] = f
	}
}
