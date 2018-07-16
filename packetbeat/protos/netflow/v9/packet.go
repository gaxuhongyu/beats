package v9

import (
	"encoding/binary"
	"io"
	"time"
)

const (
	// Version Netflow v9 Packet Header is must 0x0009
	Version uint16 = 0x0009
)

// FlowSetHeader flow set header
type FlowSetHeader struct {
	ID     uint16
	Length uint16
}

// FieldSpecifier Field Specifier
type FieldSpecifier struct {
	Type   uint16
	Length uint16
}

// Field Field
type Field struct {
	Type   uint16
	Length uint16
	Bytes  []byte
}

// DataRecord Data Record
type DataRecord struct {
	TemplateID uint16
	Fields     []Field
}

// DataFlowSet Data Flow Set
type DataFlowSet struct {
	Header  *FlowSetHeader
	Records []*Field
}

// Packet Layout,more detail see RFC3954 section 4:
//
//   +--------+-------------------------------------------+
//   |        | +----------+ +---------+ +----------+     |
//   | Packet | | Template | | Data    | | Options  |     |
//   | Header | | FlowSet  | | FlowSet | | Template | ... |
//   |        | |          | |         | | FlowSet  |     |
//   |        | +----------+ +---------+ +----------+     |
//   +--------+-------------------------------------------+
type Packet struct {
	t                       time.Time
	Header                  PacketHeader
	TemplateFlowSets        *TemplateFlowSet
	OptionsTemplateFlowSets *OptionsTemplateFlowSet
	DataFlowSets            []*DataFlowSet
}

// TemplateFlowSet ,more detail see RFC3954 section 5.2:
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       FlowSet ID = 0          |          Length               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |      Template ID 256          |         Field Count           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Field Type 1           |         Field Length 1        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Field Type 2           |         Field Length 2        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |             ...               |              ...              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Field Type N           |         Field Length N        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |      Template ID 257          |         Field Count           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Field Type 1           |         Field Length 1        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Field Type 2           |         Field Length 2        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |             ...               |              ...              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Field Type M           |         Field Length M        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |             ...               |              ...              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Template ID K          |         Field Count           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |             ...               |              ...              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type TemplateFlowSet struct {
	Header  *FlowSetHeader
	Records []*TemplateRecord
}

// TemplateFlowSets Template Records
type TemplateFlowSets []TemplateFlowSet

// TemplateRecord is a Template Record as per RFC3964 section 5.2
type TemplateRecord struct {
	TemplateID uint16
	FieldCount uint16
	Fields     []FieldSpecifier
}

// OptionsTemplateFlowSet ,more detail see RFC3954 section 6.1:
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       FlowSet ID = 1          |          Length               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Template ID           |      Option Scope Length      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Option Length          |       Scope 1 Field Type      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Scope 1 Field Length      |               ...             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Scope N Field Length      |      Option 1 Field Type      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Option 1 Field Length     |             ...               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Option M Field Length     |           Padding             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type OptionsTemplateFlowSet struct {
	Header         *FlowSetHeader
	TemplateID     uint16
	OptionScopeLen uint16
	OptionLen      uint16
	Fields         []FieldSpecifier
}

// PacketHeader more detail see RFC 3954 section 5.1:
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       Version Number        |             Count               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          sysUpTime    						   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | 						  UNIX Secs 						   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | 						Sequence Number 					   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | 						Source ID 							   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type PacketHeader struct {
	Version        uint16
	Count          uint16
	SysUpTime      uint32
	UnixSecs       uint32
	SequenceNumber uint32
	SourceID       uint32
}

// Unmarshal Unmarshal PacketHeader
func (ph *PacketHeader) Unmarshal(r io.ReadSeeker) error {
	if err := read(r, &ph.Version); err != nil {
		return err
	}
	if err := read(r, &ph.Count); err != nil {
		return err
	}
	if err := read(r, &ph.SysUpTime); err != nil {
		return err
	}
	if err := read(r, &ph.UnixSecs); err != nil {
		return err
	}
	if err := read(r, &ph.SequenceNumber); err != nil {
		return err
	}
	if err := read(r, &ph.SourceID); err != nil {
		return err
	}
	return nil
}

// Unmarshal Unmarshal TemplateFlowSet Records
func (tfs *TemplateFlowSet) Unmarshal(r io.ReadSeeker) error {
	leng := tfs.Header.Len()
	for {
		if leng >= tfs.Header.Length {
			break
		}
		tr := &TemplateRecord{}
		if err := tr.Unmarshal(r); err != nil {
			return err
		}
		tfs.Records = append(tfs.Records, tr)
		leng = leng + tr.Length()
	}
	return nil
}

// Unmarshal Template Record
func (tr *TemplateRecord) Unmarshal(r io.ReadSeeker) error {
	if err := read(r, &tr.TemplateID); err != nil {
		return err
	}
	if err := read(r, &tr.FieldCount); err != nil {
		return err
	}
	tr.Fields = make([]FieldSpecifier, tr.FieldCount)
	for index := uint16(0); index < tr.FieldCount; index++ {
		if err := tr.Fields[index].Unmarshal(r); err != nil {
			return err
		}
	}
	return nil
}

// DataLength Get Template data length
func (tr *TemplateRecord) DataLength() uint16 {
	var res uint16
	for _, v := range tr.Fields {
		res = res + v.Length
	}
	// temp := res % 4
	// if temp != 0 {
	// 	res = res + 4 - temp // padding
	// }
	return res
}

// GetFields Get Template all field
func (tr *TemplateRecord) GetFields() []FieldSpecifier {
	return tr.Fields
}

// Length Get Template self length
func (tr *TemplateRecord) Length() uint16 {
	return tr.FieldCount*4 + 4
}

// Length Get Template self length
func (otfs *OptionsTemplateFlowSet) Length() uint16 {
	return otfs.Header.Length
}

// DataLength Get Set data length
func (otfs *OptionsTemplateFlowSet) DataLength() uint16 {
	var res uint16
	for _, v := range otfs.Fields {
		res = res + v.Length
	}
	return res
}

// GetFields Get Template all field
func (otfs *OptionsTemplateFlowSet) GetFields() []FieldSpecifier {
	return otfs.Fields
}

// Unmarshal Field Specifier
func (fs *FieldSpecifier) Unmarshal(r io.ReadSeeker) error {
	if err := read(r, &fs.Type); err != nil {
		return err
	}
	if err := read(r, &fs.Length); err != nil {
		return err
	}
	return nil
}

// Unmarshal Data Flow Set Unmarshal
func (dfs *DataFlowSet) Unmarshal(r io.ReadSeeker, t Template) error {
	var dLen uint16
	fields := t.GetFields()
	for i := uint16(0); i < t.GetFieldCount(); i++ {
		f := &Field{}
		f.Type = fields[i].Type
		f.Length = fields[i].Length
		dLen = dLen + f.Length
		f.Bytes = make([]byte, f.Length)
		if _, err := r.Read(f.Bytes); err != nil {
			return err
		}
		dfs.Records = append(dfs.Records, f)
	}
	// skip padding
	// r.Seek(int64(t.Length()-dfs.Header.Len()-dLen), 1)
	return nil
}

// Unmarshal Get Flow Set Header
func (fsh *FlowSetHeader) Unmarshal(r io.ReadSeeker) error {
	if err := read(r, &fsh.ID); err != nil {
		return err
	}
	if err := read(r, &fsh.Length); err != nil {
		return err
	}
	return nil
}

// Len Get Flow Set Header
func (fsh *FlowSetHeader) Len() uint16 {
	return 4
}

// Unmarshal Get Option Template Flow Set
func (otfs *OptionsTemplateFlowSet) Unmarshal(r io.ReadSeeker) error {
	if err := read(r, &otfs.TemplateID); err != nil {
		return err
	}
	if err := read(r, &otfs.OptionScopeLen); err != nil {
		return err
	}
	if err := read(r, &otfs.OptionLen); err != nil {
		return err
	}
	l := otfs.OptionScopeLen/4 + otfs.OptionLen/4
	otfs.Fields = make([]FieldSpecifier, l)
	for i := uint16(0); i < l; i++ {
		if err := otfs.Fields[i].Unmarshal(r); err != nil {
			return err
		}
	}
	return nil
}

// GetFieldCount Get Template Field Count
func (tr *TemplateRecord) GetFieldCount() uint16 {
	return tr.FieldCount
}

// GetFieldCount Get Field Count
func (otfs *OptionsTemplateFlowSet) GetFieldCount() uint16 {
	return (otfs.OptionLen + otfs.OptionScopeLen) / 4
}

func read(r io.Reader, v interface{}) error {
	return binary.Read(r, binary.BigEndian, v)
}
