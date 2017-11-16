package sflow

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

var TestEthernetRawData = []byte{
	0x00, 0x00, 0x05, 0xEE, 0x3C, 0x8C, 0x40, 0xBC,
	0x32, 0x3F, 0x00, 0x00, 0xC8, 0x8D, 0x83, 0xAA,
	0x1C, 0x22, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
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
