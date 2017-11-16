package sflow

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

var TestExtSwitchRawData = []byte{
	0x00, 0x00, 0x0F, 0xA0, 0x00, 0x00, 0xB1, 0x1B,
	0x00, 0x00, 0xC0, 0x91, 0x00, 0x00, 0xF0, 0xB0,
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
