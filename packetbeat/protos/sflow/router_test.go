package sflow

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

var TestExtRouterRawData = []byte{
	0x00, 0x00, 0x00, 0x01, 0xAC, 0x14, 0x02, 0x33,
	0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x16,
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
