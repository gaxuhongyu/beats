package sflow

import "io"

// SFExtSwitchData Extended Vlan priority data
type SFExtSwitchData struct {
	Tag             uint32 // must 1001
	Length          uint32 // total struct length not include Tag and Length
	SrcVlanID       uint32 // in vlan id
	SrcVlanPriority uint32 // in vlan priority
	DstVlanID       uint32 // out vlan id
	DstVlanPriority uint32 // out vlan priority
}

func decodeExtSwitch(r io.ReadSeeker) (*SFExtSwitchData, error) {
	var (
		es  = &SFExtSwitchData{}
		err error
	)
	if err = read(r, &es.SrcVlanID); err != nil {
		return nil, err
	}
	if err = read(r, &es.SrcVlanPriority); err != nil {
		return nil, err
	}
	if err = read(r, &es.DstVlanID); err != nil {
		return nil, err
	}
	if err = read(r, &es.DstVlanPriority); err != nil {
		return nil, err
	}
	return es, nil
}
