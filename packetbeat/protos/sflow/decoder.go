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
	reader io.ReadSeeker
	filter []uint32 // Filter data format(s)
	ts     time.Time
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

const (
	// SFSampleTag flow sample tag
	SFSampleTag = uint32(3)
	// SFCounterTag Counter sample tag
	SFCounterTag = uint32(4)
	// SFRawPacketTag raw packet header tag
	SFRawPacketTag = uint32(1)
	// SFEthernetTag ethernet frame header tag
	SFEthernetTag = uint32(2)
	// SFIPV4Tag ipv4 header tag
	SFIPV4Tag = uint32(3)
	// SFExtRouterDataTag extended router tag
	SFExtRouterDataTag = uint32(1002)
	// SFExtSwitchDataTag extended vlan tag
	SFExtSwitchDataTag = uint32(1001)
)

// NewSFDecoder constructs new sflow decoder
func NewSFDecoder(r io.ReadSeeker, f []uint32) SFDecoder {
	return SFDecoder{
		reader: r,
		filter: f,
	}
}

// SFDecode decodes sFlow data
func (d *SFDecoder) SFDecode() ([]*SFTransaction, error) {
	var data []*SFTransaction
	datagram, err := d.sfHeaderDecode()
	if err != nil {
		return nil, err
	}
	for i := uint32(0); i < datagram.SamplesNo; i++ {
		trans := &SFTransaction{
			t: time.Now(),
		}
		sfTypeFormat, sfDataLength, err := getSampleInfo(d.reader)
		if err != nil {
			return nil, err
		}

		switch sfTypeFormat {
		case SFSampleTag:
			trans.datagram = datagram
			h, err := flowSampleDecode(d.reader, sfDataLength)
			if err != nil {
				debugf("flowSampleDecode Decode Error:%s", err.Error())
				return nil, err
			}
			trans.data = h
		case SFCounterTag:
			d.reader.Seek(int64(sfDataLength), 1)
		default:
			d.reader.Seek(int64(sfDataLength), 1)
		}
		data = append(data, trans)
	}
	return data, nil
}

func (d *SFDecoder) sfHeaderDecode() (*SFDatagram, error) {
	var (
		datagram = &SFDatagram{}
		ipLen    = 4
		err      error
	)

	if err = read(d.reader, &datagram.Version); err != nil {
		return nil, err
	}

	if datagram.Version != 5 {
		return nil, errSFVersionNotSupport
	}

	if err = read(d.reader, &datagram.IPVersion); err != nil {
		return nil, err
	}

	// read the agent ip address
	if datagram.IPVersion == 2 {
		ipLen = 16
	}
	buff := make([]byte, ipLen)
	if _, err = d.reader.Read(buff); err != nil {
		return nil, err
	}
	datagram.AgentAddress = buff

	if err = read(d.reader, &datagram.AgentSubID); err != nil {
		return nil, err
	}
	if err = read(d.reader, &datagram.SequenceNo); err != nil {
		return nil, err
	}
	if err = read(d.reader, &datagram.SysUpTime); err != nil {
		return nil, err
	}
	if err = read(d.reader, &datagram.SamplesNo); err != nil {
		return nil, err
	}
	debugf("Unpack SFDatagram:%X", datagram)
	return datagram, nil
}

func flowSampleDecode(r io.ReadSeeker, length uint32) ([]SfTrans, error) {
	var (
		data         []SfTrans
		sampleHeader = &SFSampleHeader{}
		err          error
	)

	sampleHeader.Tag = SFSampleTag
	sampleHeader.Length = length
	if err = sampleHeader.decode(r); err != nil {
		return nil, err
	}
	data = append(data, sampleHeader)
	for i := uint32(0); i < sampleHeader.SamplesNo; i++ {
		tag, len, err := getSampleInfo(r)
		if err != nil {
			return nil, err
		}
		switch tag {
		case SFRawPacketTag:
			var raw *SFRawPacketHeader
			if raw, err = decodeRawPacketHeader(r, len); err != nil {
				debugf("Read Raw data error:%s", err.Error())
				return nil, err
			}
			raw.Tag = tag
			raw.Length = len
			debugf("Unpack SFRawPacketHeader:%X", raw)
			data = append(data, raw)
		case SFEthernetTag:
			var eth *SFEthernetHeder
			if eth, err = decodeEthernetHeder(r, len); err != nil {
				return nil, err
			}
			eth.Tag = tag
			eth.Length = len
			debugf("Unpack SFEthernetHeder:%X", eth)
			data = append(data, eth)
		case SFIPV4Tag:
			var ip *SFIPv4Data
			if ip, err = decodeSFIPv4Data(r); err != nil {
				return nil, err
			}
			ip.Tag = tag
			ip.Length = len
			debugf("Unpack SFIPv4Data:%X", ip)
			data = append(data, ip)
		case SFExtRouterDataTag:
			var er *SFExtRouterData
			if er, err = decodeExtRouter(r); err != nil {
				return nil, err
			}
			er.Tag = tag
			er.Length = len
			debugf("Unpack SFExtRouterData:%X", er)
			data = append(data, er)
		case SFExtSwitchDataTag:
			var es *SFExtSwitchData
			if es, err = decodeExtSwitch(r); err != nil {
				return nil, err
			}
			es.Tag = tag
			es.Length = len
			debugf("Unpack SFExtSwitchData:%X", es)
			data = append(data, es)
		default:
			r.Seek(int64(len), 1)
			debugf("Not support tag :%d", tag)
		}
	}
	return data, err
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
