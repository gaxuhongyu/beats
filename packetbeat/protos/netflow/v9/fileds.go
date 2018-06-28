package v9

import (
	"encoding/binary"
	"fmt"
	"net"
)

// TemplateInfo save Template data
var filedsInfo map[string]*filed

var fileds = [][3]string{
	{"1", "frame_length", "uint64"},
	{"2", "packets", "uint64"},
	// {"3", "flows", "uint32"},
	{"4", "ip_protocol", "uint8"},
	{"5", "tos", "uint8"},
	{"6", "tcp_flags", "uint8"},
	{"7", "src_port", "uint16"},
	{"8", "src_ip", "ip"},
	{"9", "src_mask", "uint8"},
	{"10", "input_interface_value", "uint32"},
	{"11", "dst_port", "uint16"},
	{"12", "dst_ip", "ip"},
	{"13", "dst_mask", "uint8"},
	{"14", "output_interface_value", "uint32"},
	{"15", "next_hop", "ip"},
	{"16", "src_as", "uint16"},
	{"17", "dst_as", "uint16"},
	// {"18", "bgp_ipv4_next_hop", "ip"},
	// {"19", "mul_dst_pkts", "uint32"},
	// {"20", "mul_dst_bytes", "uint32"},
	{"21", "last_switched", "time"},
	{"22", "first_switched", "time"},
	{"23", "frame_length", "uint64"},
	{"24", "packets", "uint64"},
	{"27", "src_ip", "ip"},
	{"28", "dst_ip", "ip"},
	{"29", "src_mask", "uint8"},
	{"30", "dst_mask", "uint8"},
	// {"31", "ipv6_flow_label", "uint32"},
	// {"32", "icmp_type", "uint16"},
	// {"33", "mul_igmp_type", "uint8"},
	// {"34", "sampling_interval", "uint32"},
	// {"35", "sampling_algorithm", "uint8"},
	// {"36", "flow_active_timeout", "uint16"},
	// {"37", "flow_inactive_timeout", "uint16"},
	// {"38", "engine_type", "uint8"},
	// {"39", "engine_id", "uint8"},
	// {"40", "total_bytes_exp", "uint32"},
	// {"41", "total_pkts_exp", "uint32"},
	// {"42", "total_flows_exp", "uint32"},
	// {"46", "mpls_top_label_type", "uint8"},
	// {"47", "mpls_top_label_ip_addr", "uint32"},
	// {"48", "flow_sampler_id", "uint8"},
	// {"49", "flow_sampler_mode", "uint8"},
	// {"50", "flow_sampler_random_interval", "uint32"},
	{"55", "tos", "uint8"},
	// {"56", "src_mac", "mac"},
	// {"57", "dst_mac", "mac"},
	// {"58", "src_vlan", "uint16"},
	// {"59", "dst_vlan", "uint16"},
	// {"60", "ip_version", "uint8"},
	// {"61", "direction", "uint8"},
	{"62", "next_hop", "ip"},
	// {"63", "bgp_ipv6_next_hop", "ip"},
	// {"64", "ipv6_option_headers", "uint32"},
	// {"70", "mpls_label_1", "uint32"},
	// {"71", "mpls_label_2", "uint32"},
	// {"72", "mpls_label_3", "uint32"},
	// {"73", "mpls_label_4", "uint32"},
	// {"74", "mpls_label_5", "uint32"},
	// {"75", "mpls_label_6", "uint32"},
	// {"76", "mpls_label_7", "uint32"},
	// {"77", "mpls_label_8", "uint32"},
	// {"78", "mpls_label_9", "uint32"},
	// {"79", "mpls_label_10", "uint32"},
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
