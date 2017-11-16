package sflow

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

var TestSupportSflowVersionHeader = []byte{
	0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x0A, 0x06, 0x00, 0xFE, 0x00, 0x00,
	0x00, 0x06, 0x02, 0xD5, 0x04, 0xA8, 0x9C, 0x29, 0x56, 0x82, 0x00, 0x00, 0x00, 0x05,
}

var TestUnSupportSflowVersionHeader = []byte{
	0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0x0A, 0x06, 0x00, 0xFE, 0x00, 0x00,
	0x00, 0x06, 0x02, 0xD5, 0x04, 0xA8, 0x9C, 0x29, 0x56, 0x82, 0x00, 0x00, 0x00, 0x05,
}

func Test_getSampleInfo(t *testing.T) {
	type args struct {
		r io.ReadSeeker
	}
	tests := []struct {
		name    string
		args    args
		want    uint32
		want1   uint32
		wantErr bool
	}{
		{
			name: "Test get sample info",
			args: args{
				r: bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xF4}),
			},
			want:    3,
			want1:   0xF4,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := getSampleInfo(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("getSampleInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getSampleInfo() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("getSampleInfo() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_read(t *testing.T) {
	type args struct {
		r io.Reader
		v interface{}
	}
	var a uint32
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Test read uint32",
			args: args{
				r: bytes.NewReader([]byte{0x0E, 0x3A, 0x93, 0x09}),
				v: &a,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := read(tt.args.r, tt.args.v); (err != nil) != tt.wantErr {
				t.Errorf("read() error = %v, wantErr %v", err, tt.wantErr)
			}
			if a != 0xE3A9309 {
				t.Errorf("read value = %v, want: %v", a, 0xE3A9309)
			}
		})
	}
}

func Test_decodeSflowHeader(t *testing.T) {
	type args struct {
		r io.ReadSeeker
	}
	tests := []struct {
		name    string
		args    args
		want    *SFDatagram
		wantErr bool
	}{
		{
			name: "Test decode sflow header",
			args: args{
				r: bytes.NewReader(TestSupportSflowVersionHeader),
			},
			want: &SFDatagram{
				Version:      5,
				IPVersion:    1,
				AgentAddress: []byte{0x0A, 0x06, 0x00, 0xFE},
				AgentSubID:   6,
				SequenceNo:   0x02D504A8,
				SysUpTime:    0x9C295682,
				SamplesNo:    5,
			},
			wantErr: false,
		},
		{
			name: "Test decode unsupport sflow version ",
			args: args{
				r: bytes.NewReader(TestUnSupportSflowVersionHeader),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeSflowHeader(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeSflowHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeSflowHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}
