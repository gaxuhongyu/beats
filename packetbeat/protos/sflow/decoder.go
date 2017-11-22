package sflow

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/elastic/beats/libbeat/common"
)

// SfTrans get event info interface
type SfTrans interface {
	TransInfo(event common.MapStr)
}

// SFDecoder represents sFlow decoder
type SFDecoder struct {
	reader     io.ReadSeeker
	t          time.Time
	sampleType []int
}

// SFDatagram represents sFlow datagram
type SFDatagram struct {
	Version      uint32 // Datagram version
	IPVersion    uint32 // IP version
	AgentAddress net.IP // Agent IP address
	AgentSubID   uint32 // Identifies a source of sFlow data
	SequenceNo   uint32 // Sequence of sFlow Datagrams
	SysUpTime    uint32 // Current time (in milliseconds since device last booted
	SamplesNo    uint32 // Number of samples
}

// SFTransaction represents flow sample decoded packet
type SFTransaction struct {
	t        time.Time
	datagram *SFDatagram
	data     []SfTrans
}

var (
	errDataLengthUnknown   = errors.New("the sflow data length is unknown")
	errSFVersionNotSupport = errors.New("the sflow version doesn't support")
)

//Spec http://www.sflow.org/developers/diagrams/sFlowV5Sample.pdf
const (
	// SFSampleTag flow sample tag
	SFSampleTag = uint32(1)
	// SFCounterTag counter sample tag
	SFCounterTag = uint32(2)
	// SFExtSampleTag Expanded flow sample tag
	SFExtSampleTag = uint32(3)
	// SFExtCounterTag Expanded Counter sample tag
	SFExtCounterTag = uint32(4)
)

// NewSFDecoder constructs new sflow decoder
func NewSFDecoder(r io.ReadSeeker, t time.Time, stype []int) SFDecoder {
	return SFDecoder{
		reader:     r,
		t:          t,
		sampleType: stype,
	}
}

// SFDecode decodes sFlow
func (d *SFDecoder) SFDecode() ([]*SFTransaction, error) {
	var data []*SFTransaction
	datagram, err := decodeSflowHeader(d.reader)
	if err != nil {
		return nil, err
	}
	for i := uint32(0); i < datagram.SamplesNo; i++ {
		typeFormat, dataLength, err := getSampleInfo(d.reader)
		if err != nil {
			return nil, err
		}
		if m := d.isDecode(typeFormat); !m {
			d.reader.Seek(int64(dataLength), 1)
			continue
		}
		trans, err := decodeSflowData(d.reader, typeFormat, dataLength)
		if err != nil {
			return nil, err
		}
		trans.t = d.t
		trans.datagram = datagram
		data = append(data, trans)
	}
	return data, nil
}

func (d *SFDecoder) isDecode(formart uint32) bool {
	for _, v := range d.sampleType {
		if uint32(v) == formart {
			return true
		}
	}
	return false
}

// decodes sFlow body(include sample and counter info)
func decodeSflowData(r io.ReadSeeker, tag, length uint32) (*SFTransaction, error) {
	trans := &SFTransaction{}

	switch tag {
	case SFSampleTag:
		r.Seek(int64(length), 1)
	case SFCounterTag:
		r.Seek(int64(length), 1)
	case SFExtSampleTag:
		h, err := flowExpandedSampleDecode(r, length)
		if err != nil {
			debugf("flowExpandedSampleDecode Decode Error:%s", err.Error())
			return nil, err
		}
		trans.data = h
	case SFExtCounterTag:
		debugf("Sflow Ext Counter data: %v", r)
		r.Seek(int64(length), 1)
	default:
		r.Seek(int64(length), 1)
	}
	return trans, nil
}

// decodes sFlow header,here is spec http://www.sflow.org/developers/diagrams/sFlowV5Datagram.pdf
func decodeSflowHeader(r io.ReadSeeker) (*SFDatagram, error) {
	var (
		datagram = &SFDatagram{}
		ipLen    = 4
		err      error
	)

	if err = read(r, &datagram.Version); err != nil {
		return nil, err
	}

	if datagram.Version != 5 {
		return nil, errSFVersionNotSupport
	}

	if err = read(r, &datagram.IPVersion); err != nil {
		return nil, err
	}

	// read the agent ip address
	if datagram.IPVersion == 2 {
		ipLen = 16
	}
	buff := make([]byte, ipLen)
	if _, err = r.Read(buff); err != nil {
		return nil, err
	}
	datagram.AgentAddress = buff

	if err = read(r, &datagram.AgentSubID); err != nil {
		return nil, err
	}
	if err = read(r, &datagram.SequenceNo); err != nil {
		return nil, err
	}
	if err = read(r, &datagram.SysUpTime); err != nil {
		return nil, err
	}
	if err = read(r, &datagram.SamplesNo); err != nil {
		return nil, err
	}
	debugf("Unpack SFDatagram:%X", datagram)
	return datagram, nil
}

func getSampleInfo(r io.ReadSeeker) (uint32, uint32, error) {
	var (
		sfTypeFormat uint32
		sfDataLength uint32
		err          error
	)

	if err = read(r, &sfTypeFormat); err != nil {
		return 0, 0, err
	}

	if err = read(r, &sfDataLength); err != nil {
		return 0, 0, errDataLengthUnknown
	}
	debugf("Tag:%d,Length:%d", sfTypeFormat, sfDataLength)
	return sfTypeFormat, sfDataLength, nil
}

func read(r io.Reader, v interface{}) error {
	return binary.Read(r, binary.BigEndian, v)
}
