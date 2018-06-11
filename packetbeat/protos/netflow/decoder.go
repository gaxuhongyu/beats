package netflow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/packetbeat/protos/netflow/v9"
)

const (

	// V5 Netflow v5 Packet Header is 0x0005
	V5 = uint16(0x0005)
	// V9 Netflow v9 Packet Header is 0x0009
	V9 = uint16(0x0009)
	// IPFIX IPFIX Packet Header is 0x000A
	IPFIX = uint16(0x000A)
)

// NTrans Netflow get event info interface
type NTrans interface {
	TransInfo() []common.MapStr
}

// NFDecoder represents NetFlow decoder
type NFDecoder struct {
	reader  io.ReadSeeker
	t       time.Time
	version []int
	src     net.IP
}

// NewNFDecoder constructs new sflow decoder
func NewNFDecoder(r io.ReadSeeker, t time.Time, version []int, ip net.IP) *NFDecoder {
	return &NFDecoder{
		reader:  r,
		t:       t,
		version: version,
		src:     ip,
	}
}

// Decode Netflow packet
func (d *NFDecoder) Decode() (NTrans, error) {
	data := [2]byte{}
	if _, err := d.reader.Read(data[:]); err != nil {
		return nil, err
	}
	version := binary.BigEndian.Uint16(data[:])
	d.reader.Seek(-2, 1)
	if d.isDecode(version) {
		switch version {
		case V5:
			debugf("Skip Netflow V5 Decode")
		case V9:
			debugf("Begin Netflow V9 Decode")
			dv9 := v9.NewDecoder(d.reader, d.t, d.src)
			return dv9.Decode()
		case IPFIX:
			debugf("Skip Netflow V5 Decode")
		default:
			msg := fmt.Sprintf("Netflow Version %d not support", version)
			debugf(msg)
			return nil, errors.New(msg)
		}
	}
	return nil, nil
}

func (d *NFDecoder) isDecode(formart uint16) bool {
	for _, v := range d.version {
		if v == int(formart) {
			return true
		}
	}
	return false
}
