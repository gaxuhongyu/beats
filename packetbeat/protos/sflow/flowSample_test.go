package sflow

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/VerizonDigital/vflow/packet"
	"github.com/elastic/beats/libbeat/common"
)

var TestSampleHeaderRawData = []byte{
	0x00, 0x00, 0x9A, 0x8D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x4E, 0x20,
	0x2F, 0x2A, 0x47, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0x00, 0x00, 0x00, 0x05,
}

var TestRawPacketData = []byte{
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x05, 0xEE, 0x00, 0x00, 0x05, 0x6E, 0x00, 0x00, 0x00, 0x80, 0xC8, 0x8D, 0x83, 0xAA, 0x1C, 0x22, 0x3C, 0x8C,
	0x40, 0xBC, 0x32, 0x3F, 0x08, 0x00, 0x45, 0x00, 0x05, 0xDC, 0x53, 0x40, 0x40, 0x00, 0x3C, 0x06, 0xF3, 0x69, 0x0A, 0x17, 0x47, 0x5F, 0x0A, 0x99,
	0x96, 0x63, 0x97, 0xBF, 0x1F, 0x90, 0x23, 0xE6, 0xD6, 0xC3, 0x7B, 0xD5, 0x1D, 0x17, 0x80, 0x10, 0x01, 0xF4, 0xE5, 0xA8, 0x00, 0x00, 0x01, 0x01,
	0x08, 0x0A, 0x89, 0x6F, 0x46, 0x5E, 0x72, 0xB8, 0xC1, 0x1C, 0x3A, 0xB5, 0x58, 0x98, 0x10, 0xBC, 0x99, 0x53, 0x25, 0xC2, 0x1C, 0x00, 0xD5, 0x60,
	0xC1, 0xFE, 0x71, 0x94, 0xA0, 0xE0, 0x50, 0xAB, 0x89, 0x0B, 0x19, 0x2F, 0x4E, 0xAB, 0xF0, 0x7B, 0xE1, 0x00, 0xBC, 0xC9, 0xD0, 0x60, 0x51, 0x03,
	0x17, 0x03, 0x30, 0x3F, 0xC1, 0x08, 0x46, 0xFF, 0x84, 0x85, 0x69, 0x41, 0x42, 0x0D, 0x41, 0x0C, 0x0F, 0x6B, 0x40, 0xA1, 0x1E, 0x0F, 0x80, 0xEE,
}

var TestEthernetRawData = []byte{
	0x00, 0x00, 0x05, 0xEE, 0x3C, 0x8C, 0x40, 0xBC,
	0x32, 0x3F, 0x00, 0x00, 0xC8, 0x8D, 0x83, 0xAA,
	0x1C, 0x22, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
}

var TestIPv4RawData = []byte{
	0x00, 0x00, 0x05, 0xDC, 0x00, 0x00, 0x00, 0x06,
	0x0A, 0x17, 0x47, 0x5F, 0x0A, 0x99, 0x96, 0x63,
	0x00, 0x00, 0x97, 0xBF, 0x00, 0x00, 0x1F, 0x90,
	0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
}

var TestExtRouterRawData = []byte{
	0x00, 0x00, 0x00, 0x01, 0xAC, 0x14, 0x02, 0x33,
	0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x16,
}

var TestExtSwitchRawData = []byte{
	0x00, 0x00, 0x0F, 0xA0, 0x00, 0x00, 0xB1, 0x1B,
	0x00, 0x00, 0xC0, 0x91, 0x00, 0x00, 0xF0, 0xB0,
}

var TestflowExpandedSampleDecodeRawData = []byte{
	0x0E, 0x3A, 0x93, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x03, 0xE8, 0xA2, 0x76, 0x59, 0x6E, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD6, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0xEA,
	0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x0A, 0x06, 0x20, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x03, 0xE9,
	0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x0F, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x05, 0xF2, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x80, 0x70, 0xBA, 0xEF, 0x04,
	0xE5, 0xB5, 0x00, 0x23, 0x89, 0xCC, 0xA1, 0xFC, 0x81, 0x00, 0x0F, 0xA0, 0x08, 0x00, 0x45, 0x00, 0x05, 0xDC, 0x4C, 0x02, 0x40, 0x00, 0x33, 0x06,
	0xFA, 0x52, 0xDC, 0xAC, 0xF2, 0x8F, 0x0A, 0x06, 0x22, 0x85, 0x00, 0x50, 0xE9, 0xF8, 0xBD, 0x14, 0x3F, 0x9A, 0x4C, 0x01, 0xEC, 0x50, 0x50, 0x18,
	0x0D, 0x8C, 0x62, 0x67, 0x00, 0x00, 0xEB, 0xBF, 0x38, 0x2A, 0xFB, 0x9E, 0xCA, 0x37, 0xA3, 0x45, 0x59, 0xC8, 0x6E, 0xF5, 0x43, 0xD9, 0xBD, 0xE2,
	0x2E, 0xF1, 0x01, 0x2C, 0xAE, 0x8F, 0x71, 0xC4, 0x63, 0x59, 0xFB, 0x99, 0xDF, 0x4A, 0xFA, 0x91, 0x30, 0x1D, 0xA5, 0x42, 0xEA, 0x75, 0xDA, 0x08,
	0x72, 0x12, 0x45, 0x73, 0x93, 0xE4, 0xC2, 0xD3, 0xCA, 0xA2, 0xFC, 0x05, 0x89, 0xE8, 0xFB, 0xA0, 0x81, 0x54, 0xCF, 0xE0, 0xF4, 0x1F, 0x21, 0x73,
	0xC6, 0x08, 0x1C, 0xBB,
}

func Test_decodeExpandedSampleHeader(t *testing.T) {
	type args struct {
		r io.ReadSeeker
	}
	tests := []struct {
		name    string
		args    args
		want    *SFExpandedSampleHeader
		wantErr bool
	}{
		{
			name: "Test decode sample header",
			args: args{
				r: bytes.NewReader(TestSampleHeaderRawData),
			},
			want: &SFExpandedSampleHeader{
				Tag:          0,
				Length:       0,
				SequenceNo:   0x9A8D,
				DSClass:      0,
				DSIndex:      0x41,
				SampleRate:   0x4E20,
				SamplePool:   0x2F2A47A0,
				Drops:        0,
				InputFormat:  0,
				InputIndex:   0x41,
				OutputFormat: 0,
				OutputIndex:  0x86,
				SamplesNo:    5,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeExpandedSampleHeader(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeExpandedSampleHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeExpandedSampleHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_SampleHeaderTransInfo(t *testing.T) {
	type args struct {
		r *SFExpandedSampleHeader
	}
	testSampleHeader, _ := decodeExpandedSampleHeader(bytes.NewReader(TestSampleHeaderRawData))
	tests := []struct {
		name string
		args args
		want common.MapStr
	}{
		{
			name: "Test decode sample header",
			args: args{
				r: testSampleHeader,
			},
			want: common.MapStr{
				"drops":        uint32(0),
				"flowsrecords": uint32(0x4E20),
				"inputformat":  uint32(0),
				"inputindex":   uint32(0x41),
				"outputformat": uint32(0),
				"outputindex":  uint32(0x86),
				"samplepool":   uint32(0x2F2A47A0),
				"samplerate":   uint32(0x4E20),
				"sequenceno":   uint32(5),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := common.MapStr{}
			tt.args.r.TransInfo(got)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SampleHeader func TransInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decodeRawPacketHeader(t *testing.T) {
	type args struct {
		r      io.ReadSeeker
		length uint32
	}
	packeDecode := packet.NewPacket()
	packeData, _ := packeDecode.Decoder(TestRawPacketData[16:])
	tests := []struct {
		name    string
		args    args
		want    *SFRawPacketHeader
		wantErr bool
	}{
		{
			name: "Test decode raw packet header",
			args: args{
				r:      bytes.NewReader(TestRawPacketData),
				length: 0x90,
			},
			want: &SFRawPacketHeader{
				Tag:            0,
				Length:         0,
				HeaderProtocol: 1,
				FrameLength:    0x05EE,
				StrippedLength: 0x056E,
				HeaderLength:   0x80,
				data:           TestRawPacketData[16:],
				header:         packeData,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeRawPacketHeader(tt.args.r, tt.args.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeRawPacketHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeRawPacketHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_RawPacketHeaderTransInfo(t *testing.T) {
	type args struct {
		r *SFRawPacketHeader
	}
	testRawPacketHeader, _ := decodeRawPacketHeader(bytes.NewReader(TestRawPacketData), 0x90)
	tests := []struct {
		name string
		args args
		want common.MapStr
	}{
		{
			name: "Test decode sample header",
			args: args{
				r: testRawPacketHeader,
			},
			want: common.MapStr{
				"dstport":     int(0x1F90),
				"srcport":     int(0x97BF),
				"tcpflags":    int(0x10),
				"dstip":       string("10.153.150.99"),
				"ethertype":   2048,
				"ipprotocol":  int(6),
				"ipversion":   int(4),
				"packagesize": int(1518),
				"srcip":       string("10.23.71.95"),
				"tos":         int(0),
				"ttl":         int(0x3C),
				"vlanid":      int(0),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := common.MapStr{}
			tt.args.r.TransInfo(got)
			for key, value := range tt.want {
				if fmt.Sprintf("%v", got[key]) != fmt.Sprintf("%v", value) {
					t.Errorf("SFRawPacketHeader func TransInfo return %s = %v, want %v", key, got[key], value)
				}
			}
		})
	}
}

func Test_decodeEthernetHeder(t *testing.T) {
	type args struct {
		r      io.ReadSeeker
		length uint32
	}
	tests := []struct {
		name    string
		args    args
		want    *SFEthernetHeder
		wantErr bool
	}{
		{
			name: "Test decode ethernet header",
			args: args{
				r:      bytes.NewReader(TestEthernetRawData),
				length: 0x18,
			},
			want: &SFEthernetHeder{
				Tag:         0,
				Length:      0,
				FrameLength: 0x05EE,
				SrcMac:      "3c:8c:40:bc:32:3f",
				DstMac:      "00:00:c8:8d:83:aa",
				Header: []byte{
					0x3C, 0x8C, 0x40, 0xBC,
					0x32, 0x3F, 0x00, 0x00, 0xC8, 0x8D, 0x83, 0xAA,
					0x1C, 0x22, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeEthernetHeder(tt.args.r, tt.args.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeEthernetHeder() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeEthernetHeder() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_EthernetHederTransInfo(t *testing.T) {
	type args struct {
		r *SFEthernetHeder
	}
	testEthernetHeder, _ := decodeEthernetHeder(bytes.NewReader(TestEthernetRawData), 0x18)
	tests := []struct {
		name string
		args args
		want common.MapStr
	}{
		{
			name: "Test decode SFEthernetHeder TransInfo",
			args: args{
				r: testEthernetHeder,
			},
			want: common.MapStr{
				"srcmac": "3c:8c:40:bc:32:3f",
				"dstmac": "00:00:c8:8d:83:aa",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := common.MapStr{}
			tt.args.r.TransInfo(got)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SFEthernetHeder func TransInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decodeSFIPv4Data(t *testing.T) {
	type args struct {
		r io.ReadSeeker
	}
	tests := []struct {
		name    string
		args    args
		want    *SFIPv4Data
		wantErr bool
	}{
		{
			name: "Test decode IPv4 data",
			args: args{
				r: bytes.NewReader(TestIPv4RawData),
			},
			want: &SFIPv4Data{
				Tag:         0,
				Length:      0,
				FrameLength: 0x05DC,
				Protocol:    6,
				SrcIP:       []byte{0x0A, 0x17, 0x47, 0x5F},
				DstIP:       []byte{0x0A, 0x99, 0x96, 0x63},
				SrcPort:     0x97BF,
				DstPort:     0x1F90,
				TCPFlags:    0x10,
				Tos:         0,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeSFIPv4Data(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeSFIPv4Data() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeSFIPv4Data() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_SFIPv4DataTransInfo(t *testing.T) {
	type args struct {
		r *SFIPv4Data
	}
	testSFIPv4Data, _ := decodeSFIPv4Data(bytes.NewReader(TestIPv4RawData))
	tests := []struct {
		name string
		args args
		want common.MapStr
	}{
		{
			name: "Test SFIPv4Data TransInfo func",
			args: args{
				r: testSFIPv4Data,
			},
			want: common.MapStr{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := common.MapStr{}
			tt.args.r.TransInfo(got)
			// for key, value := range tt.want {
			// 	if fmt.Sprintf("%v", got[key]) != fmt.Sprintf("%v", value) {
			// 		t.Errorf("SFRawPacketHeader func TransInfo return %s = %v, want %v", key, got[key], value)
			// 	}
			// }
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SFEthernetHeder func TransInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}
func Test_decodeExtRouter(t *testing.T) {
	type args struct {
		r io.ReadSeeker
	}
	tests := []struct {
		name    string
		args    args
		want    *SFExtRouterData
		wantErr bool
	}{
		{
			name: "Test decode ext router",
			args: args{
				r: bytes.NewReader(TestExtRouterRawData),
			},
			want: &SFExtRouterData{
				Tag:        0,
				Length:     0,
				IPVersion:  1,
				NextHop:    []byte{0xAC, 0x14, 0x02, 0x33},
				SrcMaskLen: 0x16,
				DstMaskLen: 0x16,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeExtRouter(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeExtRouter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeExtRouter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_SFExtRouterDataTransInfo(t *testing.T) {
	type args struct {
		r *SFExtRouterData
	}
	testSFExtRouterData, _ := decodeExtRouter(bytes.NewReader(TestExtRouterRawData))
	tests := []struct {
		name string
		args args
		want common.MapStr
	}{
		{
			name: "Test SFExtRouterData TransInfo func",
			args: args{
				r: testSFExtRouterData,
			},
			want: common.MapStr{
				"dstmasklen": 22,
				"nextHop":    "172.20.2.51",
				"srcmasklen": 22,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := common.MapStr{}
			tt.args.r.TransInfo(got)
			for key, value := range tt.want {
				if fmt.Sprintf("%v", got[key]) != fmt.Sprintf("%v", value) {
					t.Errorf("SFRawPacketHeader func TransInfo return %s = %v, want %v", key, got[key], value)
				}
			}
			// if !reflect.DeepEqual(got, tt.want) {
			// 	t.Errorf("SFEthernetHeder func TransInfo() = %v, want %v", got, tt.want)
			// }
		})
	}
}

func Test_decodeExtSwitch(t *testing.T) {
	type args struct {
		r io.ReadSeeker
	}
	tests := []struct {
		name    string
		args    args
		want    *SFExtSwitchData
		wantErr bool
	}{
		{
			name: "Test decode ext switch",
			args: args{
				r: bytes.NewReader(TestExtSwitchRawData),
			},
			want: &SFExtSwitchData{
				Tag:             0,
				Length:          0,
				SrcVlanID:       0x0FA0,
				SrcVlanPriority: 0xB11B,
				DstVlanID:       0xC091,
				DstVlanPriority: 0xF0B0,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeExtSwitch(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeExtSwitch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeExtSwitch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_SFExtSwitchDataTransInfo(t *testing.T) {
	type args struct {
		r *SFExtSwitchData
	}
	testExtSwitchData, _ := decodeExtSwitch(bytes.NewReader(TestExtSwitchRawData))
	tests := []struct {
		name string
		args args
		want common.MapStr
	}{
		{
			name: "Test SFExtSwitchData TransInfo func",
			args: args{
				r: testExtSwitchData,
			},
			want: common.MapStr{
				"dstvlanid": 0xC091,
				"srcvlanid": 0xFA0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := common.MapStr{}
			tt.args.r.TransInfo(got)
			for key, value := range tt.want {
				if fmt.Sprintf("%v", got[key]) != fmt.Sprintf("%v", value) {
					t.Errorf("SFRawPacketHeader func TransInfo return %s = %v, want %v", key, got[key], value)
				}
			}
		})
	}
}

func Test_flowExpandedSampleDecode(t *testing.T) {
	var tran []SfTrans
	type args struct {
		r      io.ReadSeeker
		length uint32
	}
	r := bytes.NewReader(TestflowExpandedSampleDecodeRawData)
	sh, _ := decodeExpandedSampleHeader(r)
	sh.Tag = SFExtSampleTag
	sh.Length = 0xF4
	tran = append(tran, sh)
	r.Seek(int64(8), 1)
	er, _ := decodeExtRouter(r)
	er.Tag = SFExtRouterDataFormat
	er.Length = 0x10
	tran = append(tran, er)
	r.Seek(int64(8), 1)
	es, _ := decodeExtSwitch(r)
	es.Tag = SFExtSwitchDataFormat
	es.Length = 0x10
	tran = append(tran, es)
	r.Seek(int64(8), 1)
	ra, _ := decodeRawPacketHeader(r, 0x90)
	ra.Tag = SFRawPacketFormat
	ra.Length = 0x90
	tran = append(tran, ra)
	tests := []struct {
		name    string
		args    args
		want    []SfTrans
		wantErr bool
	}{
		{
			name: "Test decode flow sample",
			args: args{
				r:      bytes.NewReader(TestflowExpandedSampleDecodeRawData),
				length: 0xF4,
			},
			want:    tran,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := flowExpandedSampleDecode(tt.args.r, tt.args.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("flowExpandedSampleDecode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("flowExpandedSampleDecode() = %v, want %v", got, tt.want)
			}
		})
	}
}
