package atp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	Magic      uint16 = 0x4154
	VersionV1  uint8  = 1
	HeaderSize        = 26

	TypeHello       uint8 = 0x01
	TypeAuth        uint8 = 0x02
	TypeOpenStream  uint8 = 0x03
	TypeData        uint8 = 0x04
	TypeWindowUp    uint8 = 0x05
	TypePing        uint8 = 0x06
	TypeCloseStream uint8 = 0x07
	TypeCloseSess   uint8 = 0x08
	TypeError       uint8 = 0x09
	TypeDatagram    uint8 = 0x0A
)

const (
	TLVClientName   uint16 = 1
	TLVClientNonce  uint16 = 2
	TLVAuthToken    uint16 = 3
	TLVAuthPassword uint16 = 9
	TLVResumeTicket uint16 = 10
	TLVResumeReq    uint16 = 11
	TLVResumeAccept uint16 = 12
	TLVStatus       uint16 = 4
	TLVSessionID    uint16 = 5
	TLVServerNonce  uint16 = 6
	TLVErrorCode    uint16 = 7
	TLVErrorReason  uint16 = 8
	TLVOpenNetwork  uint16 = 0x0101
	TLVOpenHost     uint16 = 0x0102
	TLVOpenPort     uint16 = 0x0103
	TLVOpenDomain   uint16 = 0x0104
	TLVCoverMode    uint16 = 0x0201
	TLVCoverPadding uint16 = 0x0202
	TLVCoverTS      uint16 = 0x0203
	TLVCoverRandom  uint16 = 0x0204
	TLVCoverToken   uint16 = 0x0205
	TLVCoverPass    uint16 = 0x0206
	TLVCoverResume  uint16 = 0x0207
	NetworkTCP      uint8  = 1
	NetworkUDP      uint8  = 2
)

var (
	ErrInvalidHeaderSize   = errors.New("invalid header size")
	ErrBadMagic            = errors.New("bad magic")
	ErrBadHeaderCRC        = errors.New("bad header crc")
	ErrPayloadTooLarge     = errors.New("payload too large")
	ErrInvalidTLV          = errors.New("invalid tlv")
	ErrInvalidControlFrame = errors.New("invalid control frame")
)

type Header struct {
	Magic     uint16
	Version   uint8
	Type      uint8
	Flags     uint8
	Reserved  uint8
	SessionID uint64
	StreamID  uint32
	Seq       uint32
	Length    uint16
	HeaderCRC uint16
}

type Frame struct {
	Header  Header
	Payload []byte
}

func (h Header) MarshalBinary() ([]byte, error) {
	b := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(b[0:2], h.Magic)
	b[2] = h.Version
	b[3] = h.Type
	b[4] = h.Flags
	b[5] = h.Reserved
	binary.BigEndian.PutUint64(b[6:14], h.SessionID)
	binary.BigEndian.PutUint32(b[14:18], h.StreamID)
	binary.BigEndian.PutUint32(b[18:22], h.Seq)
	binary.BigEndian.PutUint16(b[22:24], h.Length)
	binary.BigEndian.PutUint16(b[24:26], headerCRC(b[:24]))
	return b, nil
}

func (h *Header) UnmarshalBinary(b []byte) error {
	if len(b) != HeaderSize {
		return ErrInvalidHeaderSize
	}
	h.Magic = binary.BigEndian.Uint16(b[0:2])
	if h.Magic != Magic {
		return ErrBadMagic
	}
	h.Version = b[2]
	h.Type = b[3]
	h.Flags = b[4]
	h.Reserved = b[5]
	h.SessionID = binary.BigEndian.Uint64(b[6:14])
	h.StreamID = binary.BigEndian.Uint32(b[14:18])
	h.Seq = binary.BigEndian.Uint32(b[18:22])
	h.Length = binary.BigEndian.Uint16(b[22:24])
	h.HeaderCRC = binary.BigEndian.Uint16(b[24:26])
	if h.HeaderCRC != headerCRC(b[:24]) {
		return ErrBadHeaderCRC
	}
	return nil
}

func ReadFrame(r io.Reader) (*Frame, error) {
	head := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	var h Header
	if err := h.UnmarshalBinary(head); err != nil {
		return nil, err
	}
	payload := make([]byte, int(h.Length))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return &Frame{Header: h, Payload: payload}, nil
}

func WriteFrame(w io.Writer, f *Frame) error {
	if len(f.Payload) > 0xFFFF {
		return ErrPayloadTooLarge
	}
	h := f.Header
	h.Length = uint16(len(f.Payload))
	hb, err := h.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err = w.Write(hb); err != nil {
		return err
	}
	if len(f.Payload) == 0 {
		return nil
	}
	_, err = w.Write(f.Payload)
	return err
}

type TLV struct {
	Type  uint16
	Value []byte
}

func EncodeTLVs(items []TLV) ([]byte, error) {
	total := 0
	for _, it := range items {
		if len(it.Value) > 0xFFFF {
			return nil, ErrInvalidTLV
		}
		total += 4 + len(it.Value)
	}
	out := make([]byte, total)
	off := 0
	for _, it := range items {
		binary.BigEndian.PutUint16(out[off:off+2], it.Type)
		binary.BigEndian.PutUint16(out[off+2:off+4], uint16(len(it.Value)))
		copy(out[off+4:off+4+len(it.Value)], it.Value)
		off += 4 + len(it.Value)
	}
	return out, nil
}

func DecodeTLVs(b []byte) ([]TLV, error) {
	items := make([]TLV, 0, 4)
	off := 0
	for off < len(b) {
		if len(b)-off < 4 {
			return nil, ErrInvalidTLV
		}
		t := binary.BigEndian.Uint16(b[off : off+2])
		l := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if off+l > len(b) {
			return nil, ErrInvalidTLV
		}
		v := make([]byte, l)
		copy(v, b[off:off+l])
		off += l
		items = append(items, TLV{Type: t, Value: v})
	}
	return items, nil
}

type OpenRequest struct {
	Network uint8
	Host    string
	Port    uint16
	Domain  string
}

func EncodeOpenRequest(req OpenRequest) ([]byte, error) {
	if (req.Network != NetworkTCP && req.Network != NetworkUDP) || req.Host == "" || req.Port == 0 {
		return nil, fmt.Errorf("%w: invalid open request", ErrInvalidControlFrame)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, req.Port)
	tlvs := []TLV{
		{Type: TLVOpenNetwork, Value: []byte{req.Network}},
		{Type: TLVOpenHost, Value: []byte(req.Host)},
		{Type: TLVOpenPort, Value: portBytes},
	}
	if req.Domain != "" {
		tlvs = append(tlvs, TLV{Type: TLVOpenDomain, Value: []byte(req.Domain)})
	}
	return EncodeTLVs(tlvs)
}

func DecodeOpenRequest(payload []byte) (OpenRequest, error) {
	items, err := DecodeTLVs(payload)
	if err != nil {
		return OpenRequest{}, err
	}
	var req OpenRequest
	for _, it := range items {
		switch it.Type {
		case TLVOpenNetwork:
			if len(it.Value) != 1 {
				return OpenRequest{}, fmt.Errorf("%w: invalid network length", ErrInvalidControlFrame)
			}
			req.Network = it.Value[0]
		case TLVOpenHost:
			req.Host = string(it.Value)
		case TLVOpenPort:
			if len(it.Value) != 2 {
				return OpenRequest{}, fmt.Errorf("%w: invalid port length", ErrInvalidControlFrame)
			}
			req.Port = binary.BigEndian.Uint16(it.Value)
		case TLVOpenDomain:
			req.Domain = string(it.Value)
		}
	}
	if (req.Network != NetworkTCP && req.Network != NetworkUDP) || req.Host == "" || req.Port == 0 {
		return OpenRequest{}, fmt.Errorf("%w: missing required open fields", ErrInvalidControlFrame)
	}
	return req, nil
}

func ParseTLVMap(payload []byte) (map[uint16][]byte, error) {
	items, err := DecodeTLVs(payload)
	if err != nil {
		return nil, err
	}
	out := make(map[uint16][]byte, len(items))
	for _, it := range items {
		out[it.Type] = it.Value
	}
	return out, nil
}

func headerCRC(data []byte) uint16 {
	return uint16(crc32.ChecksumIEEE(data) & 0xFFFF)
}
