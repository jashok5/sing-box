package atp

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	origin := &Frame{
		Header: Header{
			Magic:     Magic,
			Version:   VersionV1,
			Type:      TypeDatagram,
			SessionID: 7,
			StreamID:  2,
			Seq:       3,
		},
		Payload: []byte("udp"),
	}
	var b bytes.Buffer
	if err := WriteFrame(&b, origin); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	decoded, err := ReadFrame(&b)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if decoded.Header.Type != TypeDatagram || decoded.Header.SessionID != 7 || decoded.Header.StreamID != 2 || string(decoded.Payload) != "udp" {
		t.Fatalf("unexpected decode result: %+v payload=%q", decoded.Header, string(decoded.Payload))
	}
}

func TestOpenRequestRoundTrip(t *testing.T) {
	payload, err := EncodeOpenRequest(OpenRequest{Network: NetworkUDP, Host: "8.8.8.8", Port: 53})
	if err != nil {
		t.Fatalf("encode open request: %v", err)
	}
	req, err := DecodeOpenRequest(payload)
	if err != nil {
		t.Fatalf("decode open request: %v", err)
	}
	if req.Network != NetworkUDP || req.Host != "8.8.8.8" || req.Port != 53 {
		t.Fatalf("unexpected request: %+v", req)
	}
}
