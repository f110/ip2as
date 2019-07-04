package mrt

import (
	"bytes"
	"testing"
)

func TestReader_Scan(t *testing.T) {
	// Timestamp = 0x5d1d4180
	// Type = 0x000d (13 - TableDumpv2)
	// SubType = 0x0001 (1 - PeerIndexTable)
	// Length = 0x0000033b (827)
	input := []byte{
		0x5d, 0x1d, 0x41, 0x80, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x03, 0x3b,
		0x80, 0xdf, 0x33, 0x66, 0x00, 0x00, 0x00, 0x3f, 0x02, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x25, 0x8b,
		0x8b, 0x11, 0x25, 0x8b, 0x8b, 0x11, 0x00, 0x00, 0xe2, 0x0a, 0x02, 0x00,
		0x00, 0x00, 0x00, 0x43, 0xdb, 0xc0, 0x12, 0x00, 0x00, 0x4c, 0xc5, 0x02,
		0x00, 0x00, 0x00, 0x00, 0xc6, 0x3a, 0xc6, 0xff, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0xc3, 0x16, 0xd8, 0xbc, 0x00, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x57, 0x79, 0x40, 0x04, 0x00, 0x00,
		0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x57, 0x79, 0x40, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0xc6, 0x3a, 0xc6, 0xff,
		0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x45, 0xb8,
		0xc1, 0x00, 0x00, 0x0d, 0x1c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x65,
		0x6e, 0x02, 0x00, 0x00, 0x36, 0xed, 0x02, 0x0c, 0x00, 0x01, 0x3f, 0x0c,
		0x00, 0x01, 0x3f, 0x00, 0x00, 0x1b, 0x6a, 0x02, 0xb8, 0x5f, 0xf5, 0x13,
		0x2d, 0x3d, 0x00, 0x55, 0x00, 0x00, 0x58, 0x7c, 0x02, 0x40, 0x39, 0x1c,
		0xf1, 0x40, 0x39, 0x1c, 0xf1, 0x00, 0x00, 0x2d, 0x11, 0x02, 0xd8, 0xda,
		0xfc, 0xa4, 0x40, 0x47, 0x89, 0xf1, 0x00, 0x00, 0x1b, 0x1b, 0x02, 0x00,
		0x00, 0x00, 0x00, 0x42, 0xb9, 0x80, 0x01, 0x00, 0x00, 0x06, 0x84, 0x02,
		0x02, 0xff, 0xfe, 0x96, 0x50, 0x5b, 0xff, 0x89, 0x00, 0x00, 0x05, 0x13,
		0x02, 0x55, 0x72, 0x00, 0x68, 0x55, 0x72, 0x00, 0xd9, 0x00, 0x00, 0x21,
		0x2c, 0x02, 0xac, 0x10, 0x4d, 0x04, 0x57, 0x79, 0x40, 0x04, 0x00, 0x00,
		0xe0, 0x77, 0x02, 0x00, 0x00, 0x00, 0x00, 0x59, 0x95, 0xb2, 0x0a, 0x00,
		0x00, 0x0c, 0xb9, 0x02, 0x5b, 0xda, 0xb8, 0x3c, 0x5b, 0xda, 0xb8, 0x3c,
		0x00, 0x00, 0xc2, 0x7c, 0x02, 0x5b, 0xe4, 0x97, 0x01, 0x5b, 0xe4, 0x97,
		0x01, 0x00, 0x00, 0x79, 0x2b, 0x02, 0xd4, 0x49, 0x8b, 0x75, 0x5e, 0x9c,
		0xfc, 0x12, 0x00, 0x00, 0x85, 0xb0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x5f,
		0x55, 0x00, 0x02, 0x00, 0x00, 0x36, 0xed, 0x02, 0x60, 0x04, 0x00, 0x37,
		0x60, 0x04, 0x00, 0x37, 0x00, 0x00, 0x2d, 0xa6, 0x02, 0x00, 0x00, 0x00,
		0x00, 0x67, 0xf7, 0x03, 0x2d, 0x00, 0x00, 0xe4, 0x8f, 0x02, 0x69, 0x10,
		0x00, 0xf7, 0x69, 0x10, 0x00, 0xf7, 0x00, 0x00, 0x90, 0xec, 0x02, 0x81,
		0xfa, 0x01, 0x0f, 0x81, 0xfa, 0x01, 0x47, 0x00, 0x00, 0x0b, 0x62, 0x02,
		0x86, 0xde, 0x55, 0x63, 0x86, 0xde, 0x57, 0x01, 0x00, 0x00, 0x01, 0x1e,
		0x02, 0x89, 0x27, 0x03, 0x37, 0x89, 0x27, 0x03, 0x37, 0x00, 0x00, 0x02,
		0xbd, 0x02, 0x89, 0xa4, 0x10, 0x0c, 0x89, 0xa4, 0x10, 0x54, 0x00, 0x00,
		0x08, 0x68, 0x02, 0x8c, 0xc0, 0x08, 0x10, 0x8c, 0xc0, 0x08, 0x10, 0x00,
		0x00, 0xd5, 0xc8, 0x02, 0x90, 0xe4, 0xf1, 0x82, 0x90, 0xe4, 0xf1, 0x82,
		0x00, 0x00, 0x04, 0xd7, 0x02, 0x93, 0x1c, 0x07, 0x01, 0x93, 0x1c, 0x07,
		0x01, 0x00, 0x00, 0x0c, 0x3a, 0x02, 0x93, 0x1c, 0x07, 0x02, 0x93, 0x1c,
		0x07, 0x02, 0x00, 0x00, 0x0c, 0x3a, 0x02, 0x60, 0x01, 0xd1, 0x2b, 0x9a,
		0x0b, 0x0c, 0xd4, 0x00, 0x00, 0x03, 0x54, 0x02, 0x00, 0x00, 0x00, 0x00,
		0xa2, 0xf3, 0xbc, 0x02, 0x00, 0x00, 0x36, 0xed, 0x02, 0xa2, 0xfb, 0xa2,
		0x03, 0xa2, 0xfb, 0xa3, 0x02, 0x00, 0x00, 0xd2, 0x07, 0x02, 0xa7, 0x8e,
		0x42, 0x32, 0xa7, 0x8e, 0x03, 0x06, 0x00, 0x00, 0x13, 0xc0, 0x02, 0xa8,
		0xd1, 0xff, 0x38, 0xa8, 0xd1, 0xff, 0x38, 0x00, 0x00, 0x0e, 0x9d, 0x02,
		0x0a, 0x0a, 0x0a, 0xfc, 0xad, 0xcd, 0x39, 0xea, 0x00, 0x00, 0xd0, 0x74,
		0x02, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x2c, 0x74, 0x01, 0x00, 0x00, 0xbb,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xf1, 0xa4, 0x04, 0x00, 0x00,
		0x36, 0xed, 0x02, 0x3e, 0x48, 0x88, 0x95, 0xc2, 0x99, 0x00, 0xfd, 0x00,
		0x00, 0x15, 0x25, 0x02, 0xc3, 0x16, 0xd8, 0xbc, 0xc3, 0x16, 0xd8, 0xbc,
		0x00, 0x00, 0x1a, 0x6a, 0x02, 0xc2, 0x55, 0x04, 0x0d, 0xc3, 0xd0, 0x70,
		0xa1, 0x00, 0x00, 0x0c, 0xcd, 0x02, 0xc4, 0x07, 0x6a, 0xf5, 0xc4, 0x07,
		0x6a, 0xf5, 0x00, 0x00, 0x0b, 0x59, 0x02, 0xc6, 0x3a, 0xc6, 0xfe, 0xc6,
		0x3a, 0xc6, 0xfe, 0x00, 0x00, 0x05, 0x7b, 0x02, 0xc6, 0x3a, 0xc6, 0xff,
		0xc6, 0x3a, 0xc6, 0xff, 0x00, 0x00, 0x05, 0x7b, 0x02, 0x86, 0x37, 0xc8,
		0x92, 0xc6, 0x81, 0x21, 0x55, 0x00, 0x00, 0x01, 0x25, 0x02, 0xca, 0x49,
		0x28, 0x31, 0xca, 0x49, 0x28, 0x2d, 0x00, 0x00, 0x46, 0xba, 0x02, 0xca,
		0x5d, 0x08, 0xf2, 0xca, 0x5d, 0x08, 0xf2, 0x00, 0x00, 0x5f, 0x79, 0x02,
		0x3a, 0x8a, 0x60, 0xff, 0xca, 0xe8, 0x00, 0x03, 0x00, 0x00, 0x09, 0xc1,
		0x02, 0xcb, 0x3e, 0xfc, 0x53, 0xcb, 0x3e, 0xfc, 0x53, 0x00, 0x00, 0x04,
		0xc5, 0x02, 0xcb, 0xb5, 0xf8, 0xa8, 0xcb, 0xb5, 0xf8, 0xa8, 0x00, 0x00,
		0x1d, 0xec, 0x02, 0xcb, 0xbd, 0x80, 0xe9, 0xcb, 0xbd, 0x80, 0xe9, 0x00,
		0x00, 0x5c, 0x79, 0x02, 0xce, 0x18, 0xd2, 0x50, 0xce, 0x18, 0xd2, 0x50,
		0x00, 0x00, 0x0d, 0xe9, 0x02, 0x43, 0x11, 0x50, 0x99, 0xd0, 0x33, 0x86,
		0xf6, 0x00, 0x00, 0x0d, 0xdd, 0x02, 0x43, 0x10, 0xa8, 0xf1, 0xd0, 0x33,
		0x86, 0xff, 0x00, 0x00, 0x0d, 0xdd, 0x02, 0xd4, 0x42, 0x60, 0x7e, 0xd4,
		0x42, 0x60, 0x7e, 0x00, 0x00, 0x51, 0xb0, 0x02, 0x00, 0x00, 0x00, 0x00,
		0xd5, 0x90, 0x80, 0xcb, 0x00, 0x00, 0x32, 0xe6, 0x02, 0xd8, 0x12, 0x1f,
		0x66, 0xd8, 0x12, 0x1f, 0x66, 0x00, 0x00, 0x19, 0x8b, 0x02, 0x0a, 0x0a,
		0x0a, 0x0f, 0xd8, 0xdd, 0x9d, 0xa2, 0x00, 0x00, 0x9c, 0xff, 0x02, 0x8a,
		0xbb, 0x80, 0x9e, 0xd9, 0xc0, 0x59, 0x32, 0x00, 0x00, 0x0c, 0xe7,
	}

	r := NewReader(bytes.NewReader(input))
	if !r.Scan() {
		t.Fatal("expect true but got false")
	}
	msg := r.Message()
	peerIndexTable, ok := msg.(*TableDumpv2PeerIndexTable)
	if !ok {
		t.Fatal("expect TableDumpv2PeerIndexTable but not")
	}
	if peerIndexTable.CollectorBGPId != 2162111334 {
		t.Errorf("incorrect Collector BGP ID")
	}
	if len(peerIndexTable.ViewName) != 0 {
		t.Errorf("incorrect View Name Length")
	}
	if peerIndexTable.PeerCount != 63 {
		t.Errorf("incorrect Peer Count")
	}
	if len(peerIndexTable.PeerEntries) != int(peerIndexTable.PeerCount) {
		t.Fatalf("mismatch between Peer Count and PeerEntries length (%d vs %d)", peerIndexTable.PeerCount, len(peerIndexTable.PeerEntries))
	}
}
