package atp

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
	"time"
)

func buildCoverEnvelope(mode string, payload []byte) ([]byte, error) {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	padding := make([]byte, 32)
	if _, err := rand.Read(padding); err != nil {
		return nil, err
	}
	return EncodeTLVs([]TLV{
		{Type: TLVCoverMode, Value: []byte(mode)},
		{Type: TLVCoverTS, Value: ts},
		{Type: TLVCoverRandom, Value: random},
		{Type: TLVCoverPadding, Value: padding},
		{Type: TLVCoverToken, Value: payload},
	})
}

func unwrapCoverTokenMap(in map[uint16][]byte, fields ...uint16) map[uint16][]byte {
	raw := in[TLVCoverToken]
	if len(raw) == 0 {
		return in
	}
	decoded, err := ParseTLVMap(raw)
	if err != nil {
		return in
	}
	for _, field := range fields {
		if value := decoded[field]; len(value) > 0 {
			in[field] = value
		}
	}
	return in
}

func coverModeByTransport(transport string) string {
	if strings.EqualFold(strings.TrimSpace(transport), "quic") {
		return "h3"
	}
	return "h2"
}

func normalizedHelloTLVMap(in map[uint16][]byte) map[uint16][]byte {
	decoded, ok := decodeCoverTokenMap(in)
	if !ok {
		return in
	}
	mergeTLVFields(in, decoded, TLVSessionID, TLVServerNonce, TLVResumeAccept)
	return in
}

func normalizedAuthTLVMap(in map[uint16][]byte) map[uint16][]byte {
	decoded, ok := decodeCoverTokenMap(in)
	if !ok {
		return in
	}
	mergeTLVFields(in, decoded, TLVStatus, TLVResumeTicket, TLVErrorReason)
	return in
}

func decodeCoverTokenMap(in map[uint16][]byte) (map[uint16][]byte, bool) {
	raw := in[TLVCoverToken]
	if len(raw) == 0 {
		return nil, false
	}
	decoded, err := ParseTLVMap(raw)
	if err != nil {
		return nil, false
	}
	return decoded, true
}

func mergeTLVFields(dst map[uint16][]byte, src map[uint16][]byte, fields ...uint16) {
	for _, field := range fields {
		if value := src[field]; len(value) > 0 {
			dst[field] = value
		}
	}
}
