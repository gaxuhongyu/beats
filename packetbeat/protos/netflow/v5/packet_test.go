package v5

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

var TestPacketHeaderData = []byte{
	0x00, 0x05, 0x00, 0x14, 0x96, 0xC5, 0xF6, 0x3E,
	0x5B, 0x1E, 0x28, 0x51, 0x00, 0x00, 0x00, 0x00,
	0x38, 0xE0, 0xF6, 0x00, 0x00, 0x10, 0x00, 0x00,
}

var TestFlowUnmarshalData = []byte{
	0x0A, 0x02, 0x54, 0x8E, 0x0A, 0x02, 0x54, 0x4E, 0x0A, 0x06, 0x20, 0x05,
	0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0x6D,
	0x96, 0xC5, 0xF5, 0xA8, 0x96, 0xC5, 0xF5, 0xB2, 0xC0, 0x03, 0xE9, 0x24,
	0x00, 0x1B, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func TestPacketHeader_Unmarshal(t *testing.T) {
	type fields struct {
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
	type args struct {
		r io.ReadSeeker
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Test Packet Header Unmarshal Netflow V5",
			fields: fields{
				Version:          0x05,
				Count:            0x14,
				SysUpTime:        0x96C5F63E,
				UnixSecs:         0x5B1E2851,
				UnixNSecs:        0x00,
				FlowSequence:     0x38E0F600,
				EngineType:       0x00,
				EngineID:         0x10,
				SamplingInterval: 0x00,
			},
			args: args{
				r: bytes.NewReader(TestPacketHeaderData),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := &PacketHeader{
				Version:          tt.fields.Version,
				Count:            tt.fields.Count,
				SysUpTime:        tt.fields.SysUpTime,
				UnixSecs:         tt.fields.UnixSecs,
				UnixNSecs:        tt.fields.UnixNSecs,
				FlowSequence:     tt.fields.FlowSequence,
				EngineType:       tt.fields.EngineType,
				EngineID:         tt.fields.EngineID,
				SamplingInterval: tt.fields.SamplingInterval,
			}
			p := &PacketHeader{}
			if err := p.Unmarshal(tt.args.r); (err != nil) != tt.wantErr {
				t.Errorf("PacketHeader.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(p, ph) {
				t.Errorf("PacketHeader.Unmarshal() = %v, want %v", p, ph)
			}
		})
	}
}

func TestFlow_Unmarshal(t *testing.T) {
	type fields struct {
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
	type args struct {
		r io.ReadSeeker
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Test Netflow v5 Flow Unmarshal",
			fields: fields{
				SrcAddr:     []byte{0x0A, 0x02, 0x54, 0x8E},
				DstAddr:     []byte{0x0A, 0x02, 0x54, 0x4E},
				NextHop:     []byte{0x0A, 0x06, 0x20, 0x05},
				InputIndex:  0x32,
				OutPutIndex: 0x00,
				Packets:     0x04,
				FrameLength: 0x016D,
				First:       0x96C5F5A8,
				Last:        0x96C5F5B2,
				SrcPort:     0xC003,
				DstPort:     0xE924,
				Padding1:    0x00,
				TCPFlags:    0x1B,
				Protocol:    0x06,
				Tos:         0x00,
				SrcAs:       0x00,
				DstAs:       0x00,
				SrcMask:     0x00,
				DstMask:     0x00,
				Padding2:    0x00,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Flow{
				SrcAddr:     tt.fields.SrcAddr,
				DstAddr:     tt.fields.DstAddr,
				NextHop:     tt.fields.NextHop,
				InputIndex:  tt.fields.InputIndex,
				OutPutIndex: tt.fields.OutPutIndex,
				Packets:     tt.fields.Packets,
				FrameLength: tt.fields.FrameLength,
				First:       tt.fields.First,
				Last:        tt.fields.Last,
				SrcPort:     tt.fields.SrcPort,
				DstPort:     tt.fields.DstPort,
				Padding1:    tt.fields.Padding1,
				TCPFlags:    tt.fields.TCPFlags,
				Protocol:    tt.fields.Protocol,
				Tos:         tt.fields.Tos,
				SrcAs:       tt.fields.SrcAs,
				DstAs:       tt.fields.DstAs,
				SrcMask:     tt.fields.SrcMask,
				DstMask:     tt.fields.DstMask,
				Padding2:    tt.fields.Padding2,
			}
			p := &Flow{}
			if err := p.Unmarshal(tt.args.r); (err != nil) != tt.wantErr {
				t.Errorf("Flow.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(p, f) {
				t.Errorf("PacketHeader.Unmarshal() = %v, want %v", p, f)
			}
		})
	}
}
