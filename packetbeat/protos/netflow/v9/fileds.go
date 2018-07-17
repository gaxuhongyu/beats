package v9

import (
	"encoding/binary"
	"fmt"
	"net"
)

// TemplateInfo save Template data
var filedsInfo map[string]*filed

var fileds = [][3]string{
	{"1", "in_bytes", "digital"},
	{"2", "packets", "digital"},
	{"3", "flows", "digital"},
	{"4", "ip_protocol", "digital"},
	{"5", "tos", "digital"},
	{"6", "tcp_flags", "digital"},
	{"7", "src_port", "digital"},
	{"8", "src_ip", "ip"},
	{"9", "src_mask", "digital"},
	{"10", "input_interface_value", "digital"},
	{"11", "dst_port", "digital"},
	{"12", "dst_ip", "ip"},
	{"13", "dst_mask", "digital"},
	{"14", "output_interface_value", "digital"},
	{"15", "next_hop", "ip"},
	{"16", "src_as", "digital"},
	{"17", "dst_as", "digital"},
	{"18", "bgp_ipv4_next_hop", "ip"},
	{"19", "mul_dst_pkts", "digital"},
	{"20", "mul_dst_bytes", "digital"},
	{"21", "last_switched", "time"},
	{"22", "first_switched", "time"},
	{"23", "out_bytes", "digital"},
	{"24", "packets", "digital"},
	{"27", "src_ip", "ip"},
	{"28", "dst_ip", "ip"},
	{"29", "src_mask", "digital"},
	{"30", "dst_mask", "digital"},
	{"31", "ipv6_flow_label", "digital"},
	{"32", "icmp_type", "digital"},
	{"33", "mul_igmp_type", "digital"},
	{"34", "sampling_interval", "digital"},
	{"35", "sampling_algorithm", "digital"},
	{"36", "flow_active_timeout", "digital"},
	{"37", "flow_inactive_timeout", "digital"},
	{"38", "engine_type", "digital"},
	{"39", "engine_id", "digital"},
	{"40", "total_bytes_exp", "digital"},
	{"41", "total_pkts_exp", "digital"},
	{"42", "total_flows_exp", "digital"},
	{"46", "mpls_top_label_type", "digital"},
	{"47", "mpls_top_label_ip_addr", "digital"},
	{"48", "flow_sampler_id", "digital"},
	{"49", "flow_sampler_mode", "digital"},
	{"50", "flow_sampler_random_interval", "digital"},
	{"55", "tos", "digital"},
	{"56", "src_mac", "mac"},
	{"57", "dst_mac", "mac"},
	{"58", "src_vlan", "digital"},
	{"59", "dst_vlan", "digital"},
	{"60", "ip_version", "digital"},
	{"61", "direction", "digital"},
	{"62", "next_hop", "ip"},
	{"63", "bgp_ipv6_next_hop", "ip"},
	{"64", "ipv6_option_headers", "digital"},
	{"70", "mpls_label_1", "digital"},
	{"71", "mpls_label_2", "digital"},
	{"72", "mpls_label_3", "digital"},
	{"73", "mpls_label_4", "digital"},
	{"74", "mpls_label_5", "digital"},
	{"75", "mpls_label_6", "digital"},
	{"76", "mpls_label_7", "digital"},
	{"77", "mpls_label_8", "digital"},
	{"78", "mpls_label_9", "digital"},
	{"79", "mpls_label_10", "digital"},
}

// Filed filed type define
type filed struct {
	Name string
	Type string
}

// Value dff
func (f *filed) Value(d []byte) interface{} {
	switch f.Type {
	case "digital":
		switch len(d) {
		case 1:
			return uint8(d[0])
		case 2:
			return binary.BigEndian.Uint16(d[0:])
		case 3:
			return uint32(d[2]) | uint32(d[1])<<8 | uint32(d[0])<<16
		case 4:
			return binary.BigEndian.Uint32(d[0:])
		case 8:
			return binary.BigEndian.Uint64(d[0:])
		default:
			return d
		}
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
		return s
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
