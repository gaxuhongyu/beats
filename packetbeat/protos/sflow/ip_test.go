package sflow

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

var TestIPv4RawData = []byte{
	0x00, 0x00, 0x05, 0xDC, 0x00, 0x00, 0x00, 0x06,
	0x0A, 0x17, 0x47, 0x5F, 0x0A, 0x99, 0x96, 0x63,
	0x00, 0x00, 0x97, 0xBF, 0x00, 0x00, 0x1F, 0x90,
	0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
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
