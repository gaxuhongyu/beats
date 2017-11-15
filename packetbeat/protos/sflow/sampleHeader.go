package sflow

import (
	"io"

	"github.com/elastic/beats/libbeat/common"
)

// SFSampleHeader Expanded Flow sample struct
type SFSampleHeader struct {
	Tag          uint32 // must 3
	Length       uint32
	SequenceNo   uint32 // Sequence of sFlow sample
	DSClass      uint32 // data source type default 0
	DSIndex      uint32 // data source index
	SampleRate   uint32 // sample rate
	SamplePool   uint32 // sample pool packet total count
	Drops        uint32 // drop count
	InputFormat  uint32 // input port type defalut 0
	InputIndex   uint32 // input port index value
	OutputFormat uint32 // output port type defalut 0
	OutputIndex  uint32 // output port index value
	SamplesNo    uint32 // Number of flow samples
}

func (sh *SFSampleHeader) decode(r io.ReadSeeker) error {
	var err error
	if err = read(r, &sh.SequenceNo); err != nil {
		return err
	}
	if err = read(r, &sh.DSClass); err != nil {
		return err
	}
	if err = read(r, &sh.DSIndex); err != nil {
		return err
	}
	if err = read(r, &sh.SampleRate); err != nil {
		return err
	}
	if err = read(r, &sh.SamplePool); err != nil {
		return err
	}
	if err = read(r, &sh.Drops); err != nil {
		return err
	}
	if err = read(r, &sh.InputFormat); err != nil {
		return err
	}
	if err = read(r, &sh.InputIndex); err != nil {
		return err
	}
	if err = read(r, &sh.OutputFormat); err != nil {
		return err
	}
	if err = read(r, &sh.OutputIndex); err != nil {
		return err
	}
	if err = read(r, &sh.SamplesNo); err != nil {
		return err
	}
	debugf("Unpack SFSampleHeader:%X", sh)
	return nil
}

// TransInfo get trans info
func (sh *SFSampleHeader) TransInfo(event common.MapStr) {
	event["sequenceno"] = sh.SamplesNo
	event["samplerate"] = sh.SampleRate
	event["samplepool"] = sh.SamplePool
	event["drops"] = sh.Drops
	event["inputformat"] = sh.InputFormat
	event["inputindex"] = sh.InputIndex
	event["outputformat"] = sh.OutputFormat
	event["outputindex"] = sh.OutputIndex
	event["flowsrecords"] = sh.SampleRate
}
