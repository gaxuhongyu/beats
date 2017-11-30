package sflow

import (
	"errors"
	"io"

	"github.com/elastic/beats/libbeat/common"
)

// SFCounterSampleHeader Counter Sample
type SFCounterSampleHeader struct {
	Tag           uint32 // must 2 or 4
	Length        uint32 //
	SequenceNo    uint32 // sample sequence number
	SourceIDType  uint32 // 0=ifIndex|1=smonVlanDataSource|2=entPhysicalEntry
	SourceIDIndex uint32 // source id index
	SamplesNo     uint32 // Number of counter records
}

// SFGenericInterfaceCounters Generic Interface Counters see RFC2233
type SFGenericInterfaceCounters struct {
	Tag                uint32 // must 1
	Length             uint32
	IfIndex            uint32
	IfType             uint32
	IfSpeed            uint64
	IfDirection        uint32 // 0=unknown|1=full-duplex|2=half-duplex|3=in|4=out
	IfStatus           uint32 // bit 0 => ifAdminStatus 0=down|1=up, bit 1 => ifOperStatus 0=down|1=up
	IfInOctets         uint64
	IfInUcastPkts      uint32
	IfInMulticastPkts  uint32
	IfInBroadcastPkts  uint32
	IfInDiscards       uint32
	IfInErrors         uint32
	IfInUnknownProtos  uint32
	IfOutOctets        uint64
	IfOutUcastPkts     uint32
	IfOutMulticastPkts uint32
	IfOutBroadcastPkts uint32
	IfOutDiscards      uint32
	IfOutErrors        uint32
	IfPromiscuousMode  uint32
}

// SFEthernetInterfaceCounters Ethernet Interface Counters see RFC2358
type SFEthernetInterfaceCounters struct {
	Tag                                uint32 // must 2
	Length                             uint32
	Dot3StatsAlignmentErrors           uint32
	Dot3StatsFCSErrors                 uint32
	Dot3StatsSingleCollisionFrames     uint32
	Dot3StatsMultipleCollisionFrames   uint32
	Dot3StatsSQETestErrors             uint32
	Dot3StatsDeferredTransmissions     uint32
	Dot3StatsLateCollisions            uint32
	Dot3StatsExcessiveCollisions       uint32
	Dot3StatsInternalMacTransmitErrors uint32
	Dot3StatsCarrierSenseErrors        uint32
	Dot3StatsFrameTooLongs             uint32
	Dot3StatsInternalMacReceiveErrors  uint32
	Dot3StatsSymbolErrors              uint32
}

// SFTokenRingCounters Token Ring Counters see RFC1748
type SFTokenRingCounters struct {
	Tag                         uint32 // must 3
	Length                      uint32
	Dot5StatsLineErrors         uint32
	Dot5StatsACErrors           uint32
	Dot5StatsAbortTransErrors   uint32
	Dot5StatsInternalErrors     uint32
	Dot5StatsLostFrameErrors    uint32
	Dot5StatsReceiveCongestions uint32
	Dot5StatsFrameCopiedErrors  uint32
	Dot5StatsTokenErrors        uint32
	Dot5StatsSoftErrors         uint32
	Dot5StatsHardErrors         uint32
	Dot5StatsSignalLoss         uint32
	Dot5StatsTransmitBeacons    uint32
	Dot5StatsRecoverys          uint32
	Dot5StatsLobeWires          uint32
	Dot5StatsBurstErrors        uint32
	Dot5StatsRemoves            uint32
	Dot5StatsSingles            uint32
	Dot5StatsFreqErrors         uint32
}

// SF100BaseVGInterfaceCounters 100 BaseVG Interface Counters see RFC2020
type SF100BaseVGInterfaceCounters struct {
	Tag                          uint32 // must 4
	Length                       uint32
	Dot12InHighPriorityFrames    uint32
	Dot12InHighPriorityOctets    uint64
	Dot12InNormPriorityFrames    uint32
	Dot12InNormPriorityOctets    uint64
	Dot12InIPMErrors             uint32
	Dot12InOversizeFrameErrors   uint32
	Dot12InDataErrors            uint32
	Dot12InNullAddressedFrames   uint32
	Dot12OutHighPriorityFrames   uint32
	Dot12OutHighPriorityOctets   uint64
	Dot12TransitionIntoTrainings uint32
	Dot12HCInHighPriorityOctets  uint64
	Dot12HCInNormPriorityOctets  uint64
	Dot12HCOutHighPriorityOctets uint64
}

// SFVLANCounters VLAN Counters
type SFVLANCounters struct {
	Tag           uint32 // must 5
	Length        uint32
	VlanID        uint32
	Octets        uint64
	UcastPkts     uint32
	MulticastPkts uint32
	BroadcastPkts uint32
	Discards      uint32
}

// SFProcessorInformation Processor Information
type SFProcessorInformation struct {
	Tag             uint32 // must 1001
	Length          uint32
	CPU5sPercentage uint32 // 5s cpu percentage
	CPU1mPercentage uint32 // 1m cpu percentage
	CPU5mPercentage uint32 // 5m cpu percentage
	TotalMemory     uint64
	FreeMemory      uint64
}

const (
	// SFGenericInterfaceCounter Generic Interface Counters, see RFC2233
	SFGenericInterfaceCounter = uint32(1)
	// SFEthernetInterfaceCounter Ethernet Interface Counters, see RFC2358
	SFEthernetInterfaceCounter = uint32(2)
	// SFTokenRingCounter Token Ring Counters, see RFC1748
	SFTokenRingCounter = uint32(3)
	// SF100BaseVGInterfaceCounter 100 BaseVG Interface Counters see RFC2020
	SF100BaseVGInterfaceCounter = uint32(4)
	// SFVLANCounter VLAN Counters
	SFVLANCounter = uint32(5)
	// SFProcessorInfo Processor Information
	SFProcessorInfo = uint32(1001)
)

var (
	errCounterTag = errors.New("counter tag error, must 2 or 4")
)

func counterSampleDecode(r io.ReadSeeker, tag, length uint32) ([]SfTrans, error) {
	var (
		data   []SfTrans
		record SfTrans
		header *SFCounterSampleHeader
		err    error
	)

	if header, err = decodeCounterSampleHeader(r, tag); err != nil {
		return nil, err
	}
	header.Tag = tag
	header.Length = length
	data = append(data, header)
	for i := uint32(0); i < header.SamplesNo; i++ {
		if record, err = decodeCounterRecord(r); err != nil {
			return nil, err
		}
		data = append(data, record)
	}
	return data, nil
}

func decodeCounterSampleHeader(r io.ReadSeeker, tag uint32) (*SFCounterSampleHeader, error) {
	var (
		csh  = &SFCounterSampleHeader{}
		temp uint32
		err  error
	)
	if err = read(r, &csh.SequenceNo); err != nil {
		return nil, err
	}
	if err = read(r, &temp); err != nil {
		return nil, err
	}
	if tag == SFCounterTag {
		csh.SourceIDType = temp >> 24
		csh.SourceIDIndex = temp & 0x0FFF
	} else if tag == SFExtCounterTag {
		csh.SourceIDType = temp
		if err = read(r, &csh.SourceIDIndex); err != nil {
			return nil, err
		}
	} else {
		return nil, errCounterTag
	}
	if err = read(r, &csh.SamplesNo); err != nil {
		return nil, err
	}
	return csh, nil
}

// TransInfo get SFCounterSampleHeader trans info
func (sh *SFCounterSampleHeader) TransInfo(event common.MapStr) {
}

func decodeCounterRecord(r io.ReadSeeker) (SfTrans, error) {
	var result SfTrans
	tag, len, err := getSampleInfo(r)
	if err != nil {
		return nil, err
	}
	switch tag {
	case SFGenericInterfaceCounter:
		var gif *SFGenericInterfaceCounters
		if gif, err = decodeSFGenericInterfaceCounter(r); err != nil {
			return nil, err
		}
		gif.Tag = tag
		gif.Length = len
		debugf("Unpack SFGenericInterfaceCounters:%X", gif)
		result = gif
	case SFEthernetInterfaceCounter:
		var eif *SFEthernetInterfaceCounters
		if eif, err = decodeSFEthernetInterfaceCounters(r); err != nil {
			return nil, err
		}
		eif.Tag = tag
		eif.Length = len
		debugf("Unpack SFEthernetInterfaceCounters:%X", eif)
		result = eif
	case SFTokenRingCounter:
		var trc *SFTokenRingCounters
		if trc, err = decodeSFTokenRingCounters(r); err != nil {
			return nil, err
		}
		trc.Tag = tag
		trc.Length = len
		debugf("Unpack SFTokenRingCounters:%X", trc)
		result = trc
	case SF100BaseVGInterfaceCounter:
		var bvg *SF100BaseVGInterfaceCounters
		if bvg, err = decodeSF100BaseVGInterfaceCounters(r); err != nil {
			return nil, err
		}
		bvg.Tag = tag
		bvg.Length = len
		debugf("Unpack SF100BaseVGInterfaceCounters:%X", bvg)
		result = bvg
	case SFVLANCounter:
		var vlan *SFVLANCounters
		if vlan, err = decodeSFVLANCounters(r); err != nil {
			return nil, err
		}
		vlan.Tag = tag
		vlan.Length = len
		debugf("Unpack SFVLANCounters:%X", vlan)
		result = vlan
	case SFProcessorInfo:
		var info *SFProcessorInformation
		if info, err = decodeSFProcessorInformation(r); err != nil {
			return nil, err
		}
		info.Tag = tag
		info.Length = len
		debugf("Unpack SFProcessorInformation:%X", info)
		result = info
	default:
		r.Seek(int64(len), 1)
		debugf("Not support tag :%d", tag)
	}
	return result, nil
}

func decodeSFGenericInterfaceCounter(r io.ReadSeeker) (*SFGenericInterfaceCounters, error) {
	var (
		gic = &SFGenericInterfaceCounters{}
		err error
	)
	if err = read(r, &gic.IfIndex); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfType); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfSpeed); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfDirection); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfStatus); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfInOctets); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfInUcastPkts); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfInMulticastPkts); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfInBroadcastPkts); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfInDiscards); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfInErrors); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfInUnknownProtos); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfOutOctets); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfOutUcastPkts); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfOutMulticastPkts); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfOutBroadcastPkts); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfOutDiscards); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfOutErrors); err != nil {
		return nil, err
	}
	if err = read(r, &gic.IfPromiscuousMode); err != nil {
		return nil, err
	}
	return gic, nil
}

// TransInfo get SFGenericInterfaceCounters data trans info
func (vc *SFGenericInterfaceCounters) TransInfo(event common.MapStr) {

}

func decodeSFEthernetInterfaceCounters(r io.ReadSeeker) (*SFEthernetInterfaceCounters, error) {
	var (
		eif = &SFEthernetInterfaceCounters{}
		err error
	)
	if err = read(r, &eif.Dot3StatsAlignmentErrors); err != nil {
		return nil, err
	}
	if err = read(r, &eif.Dot3StatsFCSErrors); err != nil {
		return nil, err
	}
	if err = read(r, &eif.Dot3StatsSingleCollisionFrames); err != nil {
		return nil, err
	}
	if err = read(r, &eif.Dot3StatsMultipleCollisionFrames); err != nil {
		return nil, err
	}
	if err = read(r, &eif.Dot3StatsSQETestErrors); err != nil {
		return nil, err
	}
	if err = read(r, &eif.Dot3StatsDeferredTransmissions); err != nil {
		return nil, err
	}
	if err = read(r, &eif.Dot3StatsLateCollisions); err != nil {
		return nil, err
	}
	if err = read(r, &eif.Dot3StatsExcessiveCollisions); err != nil {
		return nil, err
	}
	if err = read(r, &eif.Dot3StatsInternalMacTransmitErrors); err != nil {
		return nil, err
	}
	if err = read(r, &eif.Dot3StatsCarrierSenseErrors); err != nil {
		return nil, err
	}
	if err = read(r, &eif.Dot3StatsFrameTooLongs); err != nil {
		return nil, err
	}
	if err = read(r, &eif.Dot3StatsInternalMacReceiveErrors); err != nil {
		return nil, err
	}
	if err = read(r, &eif.Dot3StatsSymbolErrors); err != nil {
		return nil, err
	}
	return eif, nil
}

// TransInfo get SFEthernetInterfaceCounters data trans info
func (vc *SFEthernetInterfaceCounters) TransInfo(event common.MapStr) {

}

func decodeSFTokenRingCounters(r io.ReadSeeker) (*SFTokenRingCounters, error) {
	var (
		trc = &SFTokenRingCounters{}
		err error
	)
	if err = read(r, &trc.Dot5StatsLineErrors); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsACErrors); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsAbortTransErrors); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsInternalErrors); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsLostFrameErrors); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsReceiveCongestions); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsFrameCopiedErrors); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsTokenErrors); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsSoftErrors); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsHardErrors); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsSignalLoss); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsTransmitBeacons); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsRecoverys); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsLobeWires); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsBurstErrors); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsRemoves); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsSingles); err != nil {
		return nil, err
	}
	if err = read(r, &trc.Dot5StatsFreqErrors); err != nil {
		return nil, err
	}
	return trc, nil
}

// TransInfo get SFTokenRingCounters data trans info
func (vc *SFTokenRingCounters) TransInfo(event common.MapStr) {

}

func decodeSF100BaseVGInterfaceCounters(r io.ReadSeeker) (*SF100BaseVGInterfaceCounters, error) {
	var (
		bvg = &SF100BaseVGInterfaceCounters{}
		err error
	)
	if err = read(r, &bvg.Dot12InHighPriorityFrames); err != nil {
		return nil, err
	}
	if err = read(r, &bvg.Dot12InHighPriorityOctets); err != nil {
		return nil, err
	}
	if err = read(r, &bvg.Dot12InNormPriorityFrames); err != nil {
		return nil, err
	}
	if err = read(r, &bvg.Dot12InNormPriorityOctets); err != nil {
		return nil, err
	}
	if err = read(r, &bvg.Dot12InIPMErrors); err != nil {
		return nil, err
	}
	if err = read(r, &bvg.Dot12InOversizeFrameErrors); err != nil {
		return nil, err
	}
	if err = read(r, &bvg.Dot12InDataErrors); err != nil {
		return nil, err
	}
	if err = read(r, &bvg.Dot12InNullAddressedFrames); err != nil {
		return nil, err
	}
	if err = read(r, &bvg.Dot12OutHighPriorityFrames); err != nil {
		return nil, err
	}
	if err = read(r, &bvg.Dot12OutHighPriorityOctets); err != nil {
		return nil, err
	}
	if err = read(r, &bvg.Dot12TransitionIntoTrainings); err != nil {
		return nil, err
	}
	if err = read(r, &bvg.Dot12HCInHighPriorityOctets); err != nil {
		return nil, err
	}
	if err = read(r, &bvg.Dot12HCInNormPriorityOctets); err != nil {
		return nil, err
	}
	if err = read(r, &bvg.Dot12HCOutHighPriorityOctets); err != nil {
		return nil, err
	}
	return bvg, nil
}

// TransInfo get SF100BaseVGInterfaceCounters data trans info
func (vc *SF100BaseVGInterfaceCounters) TransInfo(event common.MapStr) {

}

func decodeSFVLANCounters(r io.ReadSeeker) (*SFVLANCounters, error) {
	var (
		vlan = &SFVLANCounters{}
		err  error
	)
	if err = read(r, &vlan.VlanID); err != nil {
		return nil, err
	}
	if err = read(r, &vlan.Octets); err != nil {
		return nil, err
	}
	if err = read(r, &vlan.UcastPkts); err != nil {
		return nil, err
	}
	if err = read(r, &vlan.MulticastPkts); err != nil {
		return nil, err
	}
	if err = read(r, &vlan.BroadcastPkts); err != nil {
		return nil, err
	}
	if err = read(r, &vlan.Discards); err != nil {
		return nil, err
	}
	return vlan, nil
}

// TransInfo get SFVLANCounters data trans info
func (vc *SFVLANCounters) TransInfo(event common.MapStr) {

}

func decodeSFProcessorInformation(r io.ReadSeeker) (*SFProcessorInformation, error) {
	var (
		info = &SFProcessorInformation{}
		err  error
	)
	if err = read(r, &info.CPU5sPercentage); err != nil {
		return nil, err
	}
	if err = read(r, &info.CPU1mPercentage); err != nil {
		return nil, err
	}
	if err = read(r, &info.CPU5mPercentage); err != nil {
		return nil, err
	}
	if err = read(r, &info.TotalMemory); err != nil {
		return nil, err
	}
	if err = read(r, &info.FreeMemory); err != nil {
		return nil, err
	}
	return info, nil
}

// TransInfo get SFProcessorInformation data trans info
func (vc *SFProcessorInformation) TransInfo(event common.MapStr) {

}
