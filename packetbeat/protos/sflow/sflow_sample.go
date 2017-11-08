package sflow

const (
	// SFDataRawHeader is sFlow Raw Packet Header number
	SFDataRawHeader = 1

	// SFDataExtSwitch is sFlow Extended Switch Data number
	SFDataExtSwitch = 1001
)

// FlowSample represents single flow sample
type FlowSample struct {
	SequenceNo   uint32 // Incremented with each flow sample
	SourceID     byte   // sfSourceID
	SamplingRate uint32 // sfPacketSamplingRate
	SamplePool   uint32 // Total number of packets that could have been sampled
	Drops        uint32 // Number of times a packet was dropped due to lack of resources
	Input        uint32 // SNMP ifIndex of input interface
	Output       uint32 // SNMP ifIndex of input interface
	RecordsNo    uint32 // Number of records to follow
}

// SampledHeader represents sampled header
type SampledHeader struct {
	Protocol     uint32 // (enum SFLHeader_protocol)
	FrameLength  uint32 // Original length of packet before sampling
	Stripped     uint32 // Header/trailer bytes stripped by sender
	HeaderLength uint32 // Length of sampled header bytes to follow
	Header       []byte // Header bytes
}

// ExtSwitchData represents Extended Switch Data
type ExtSwitchData struct {
	SrcVlan     uint32 // The 802.1Q VLAN id of incoming frame
	SrcPriority uint32 // The 802.1p priority of incoming frame
	DstVlan     uint32 // The 802.1Q VLAN id of outgoing frame
	DstPriority uint32 // The 802.1p priority of outgoing frame
}
