package mrt

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
)

const (
	AddressFamilyIPv4 = 1
	AddressFamilyIPv6 = 2
)

const (
	TypeOSPFv2      = 11
	TypeTableDump   = 12
	TypeTableDumpv2 = 13
	TypeBGP4MP      = 16
	TypeBGP4MP_ET   = 17
	TypeISIS        = 32
	TypeISIS_ET     = 33
	TypeOSPFv3      = 48
	TypeOSPFv3_ET   = 49
)

const (
	TableDumpSubTypeIPv4 = 1
	TableDumpSubTypeIPv6 = 2
)

const (
	TableDumpv2SubTypePeerIndexTable   = 1
	TableDumpv2SubTypeRIBIPv4Unicast   = 2
	TableDumpv2SubTypeRIBIPv4Multicast = 3
	TableDumpv2SubTypeRIBIPv6Unicast   = 4
	TableDumpv2SubTypeRIBIPv6Multicast = 5
	TableDumpv2SubTypeRIBGeneric       = 6
)

const (
	BGP4MPSubTypeStateChange     = 0
	BGP4MPSubTypeMessage         = 1
	BGP4MPSubTypeMessageAS4      = 4
	BGP4MPSubTypeStateChangeAS4  = 5
	BGP4MPSubTypeMessageLocal    = 6
	BGP4MPSubTYpeMessageAS4Local = 7
)

const (
	BGP4StateIdle = iota
	BGP4StateConnect
	BGP4StateActive
	BGP4StateOpenSent
	BGP4StateOpenConfirm
	BGP4StateEstablished
)

type MRT struct {
	Timestamp   uint32
	Microsecond uint32 // Extend Timestamp format only
	Type        []byte
	SubType     []byte
	Message     []byte
}

type OSPFv2 struct {
	MRT
	RemoteIpAddress net.IP
	LocalIpAddress  net.IP
	Message         []byte
}

type TableDump struct {
	MRT
	ViewNumber     uint16
	SeqNumber      uint16
	Prefix         net.IP
	PrefixLength   uint8
	Status         byte
	OriginatedTime uint32
	PeerIpAddress  net.IP
	PeerAS         uint16
	AttrLength     uint16
	Attr           []byte
}

type TableDumpv2PeerIndexTable struct {
	MRT
	CollectorBGPId uint32
	ViewNameLength uint16
	ViewName       []byte
	PeerCount      uint16
	PeerEntries    []TableDumpv2PeerEntry
}

type TableDumpv2PeerEntry struct {
	PeerType      uint8
	PeerBGPId     uint32
	PeerIpAddress net.IP
	PeerASs       []uint16
}

type TableDumpv2RIB struct {
	MRT
	SeqNumber    uint32
	PrefixLength uint8
	Prefix       net.IP
	EntryCount   uint8
	RIBEntries   []RIBEntry
}

type TableDumpv2RIBGeneric struct {
	MRT
	SeqNumber               uint32
	AddressFamilyIdentifier []byte
	SubsequentAFI           uint8
	ReachabilityInformation []byte
	EntryCount              uint8
	RITEntries              []RIBEntry
}

type RIBEntry struct {
	PeerIndex      uint16
	OriginatedTime uint32
	AttrLength     uint8
	Attr           []byte
}

type BGP4MPStateChange struct {
	MRT
	PeerASNumber   uint16
	LocalASNumber  uint16
	InterfaceIndex uint16
	AddressFamily  uint16
	PeerIpAddress  net.IP
	LocalIpAddress net.IP
	OldState       uint16
	NewState       uint16
}

type BGP4MPMessage struct {
	MRT
	PeerASNumber   uint16
	LocalASNumber  uint16
	InterfaceIndex uint16
	AddressFamily  uint16
	PeerIpAddress  net.IP
	LocalIpAddress net.IP
	Message        []byte
}

type BGP4MPMessageAS4 struct {
	MRT
	PeerASNumber   uint32
	LocalASNumber  uint32
	InterfaceIndex uint16
	AddressFamily  uint16
	PeerIpAddress  net.IP
	LocalIpAddress net.IP
	Message        []byte
}

type BGP4MPStateChangeAS4 struct {
	MRT
	PeerASNumber   uint32
	LocalASNumber  uint32
	InterfaceIndex uint16
	AddressFamily  uint16
	PeerIpAddress  net.IP
	LocalIpAddress net.IP
	OldState       uint16
	NewState       uint16
}

type OSPFv3 struct {
	MRT
	AddressFamily   uint8
	RemoteIpAddress net.IP
	LocalIpAddress  net.IP
	Message         []byte
}

type Reader struct {
	r   *bufio.Reader
	err error
	msg *MRT
}

func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReader(r)}
}

func (r *Reader) Scan() bool {
	buf := make([]byte, 12)
	n, err := r.r.Read(buf)
	if err == io.EOF {
		return false
	}
	if err != nil {
		r.err = err
		return false
	}
	if n != 12 {
		return false
	}
	timestamp := binary.BigEndian.Uint32(buf[:4])
	typ := buf[5:6]
	subTyp := buf[7:8]
	length := binary.BigEndian.Uint32(buf[9:12])
	buf = make([]byte, length)
	n, err = r.r.Read(buf)
	if err != nil {
		r.err = err
		return false
	}
	if uint32(n) != length {
		return false
	}
	message := buf[:length]
	r.msg = &MRT{
		Timestamp: timestamp,
		Type:      typ,
		SubType:   subTyp,
		Message:   message,
	}

	return true
}

func (r *Reader) Message() *MRT {
	if r.err != nil {
		return nil
	}

	return r.msg
}

func (r *Reader) Err() error {
	return r.err
}
