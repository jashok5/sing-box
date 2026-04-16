package atp

import (
	"context"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestClientHandshakeAndTCPFlow(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- runMockATPServerTCP(server, "token-a")
	}()

	link, _, err := clientHandshake(client, "test-client", "token-a", "secret", "")
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	destination := M.ParseSocksaddrHostPort("example.com", 443)
	streamID, st, err := link.open(context.Background(), NetworkTCP, destination)
	if err != nil {
		t.Fatalf("open tcp stream failed: %v", err)
	}

	conn := newOutboundStreamConn(link, streamID, st)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tcp payload failed: %v", err)
	}
	b := make([]byte, 8)
	n, err := conn.Read(b)
	if err != nil {
		t.Fatalf("read tcp payload failed: %v", err)
	}
	if string(b[:n]) != "pong" {
		t.Fatalf("unexpected tcp response: %q", string(b[:n]))
	}

	if err = waitServerDone(serverDone); err != nil {
		t.Fatalf("mock server failed: %v", err)
	}
}

func TestClientHandshakeAndUDPFlow(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- runMockATPServerUDP(server, "token-u")
	}()

	link, _, err := clientHandshake(client, "test-client", "token-u", "secret", "")
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	destination := M.ParseSocksaddrHostPort("8.8.8.8", 53)
	streamID, st, err := link.open(context.Background(), NetworkUDP, destination)
	if err != nil {
		t.Fatalf("open udp stream failed: %v", err)
	}

	pc := newOutboundPacketConn(link, streamID, st)
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = pc.WriteTo([]byte("hello"), destination.UDPAddr()); err != nil {
		t.Fatalf("write udp datagram failed: %v", err)
	}
	b := make([]byte, 16)
	n, _, err := pc.ReadFrom(b)
	if err != nil {
		t.Fatalf("read udp datagram failed: %v", err)
	}
	if string(b[:n]) != "world" {
		t.Fatalf("unexpected udp response: %q", string(b[:n]))
	}

	if err = waitServerDone(serverDone); err != nil {
		t.Fatalf("mock server failed: %v", err)
	}
}

func TestClientHandshakeResumeAccepted(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- runMockATPResumeAcceptedServer(server, "resume-ok")
	}()

	link, ticket, err := clientHandshake(client, "test-client", "token-r", "secret", "resume-ok")
	if err != nil {
		t.Fatalf("resume handshake failed: %v", err)
	}
	if ticket != "resume-next" {
		t.Fatalf("unexpected resume ticket: %q", ticket)
	}
	_ = link.close()
	if err = waitServerDone(serverDone); err != nil {
		t.Fatalf("mock server failed: %v", err)
	}
}

func TestClientHandshakeResumeFallbackAuth(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- runMockATPResumeFallbackServer(server, "token-f")
	}()

	link, ticket, err := clientHandshake(client, "test-client", "token-f", "secret", "resume-old")
	if err != nil {
		t.Fatalf("resume fallback handshake failed: %v", err)
	}
	if ticket != "resume-fallback-next" {
		t.Fatalf("unexpected resume ticket: %q", ticket)
	}
	_ = link.close()
	if err = waitServerDone(serverDone); err != nil {
		t.Fatalf("mock server failed: %v", err)
	}
}

func waitServerDone(done <-chan error) error {
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		return net.ErrClosed
	}
}

func runMockATPServerTCP(conn net.Conn, expectToken string) error {
	hello, err := ReadFrame(conn)
	if err != nil {
		return err
	}
	if hello.Header.Type != TypeHello {
		return ErrInvalidControlFrame
	}
	sessionID := uint64(9)
	sid := make([]byte, 8)
	putSessionID(sid, sessionID)
	helloResp, _ := EncodeTLVs([]TLV{{Type: TLVSessionID, Value: sid}, {Type: TLVServerNonce, Value: []byte("nonce")}})
	if err = WriteFrame(conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: TypeHello, SessionID: sessionID, Seq: 1}, Payload: helloResp}); err != nil {
		return err
	}
	auth, err := ReadFrame(conn)
	if err != nil {
		return err
	}
	authMap, err := ParseTLVMap(auth.Payload)
	if err != nil {
		return err
	}
	if string(authMap[TLVAuthToken]) != expectToken || string(authMap[TLVAuthPassword]) != "secret" {
		return ErrInvalidControlFrame
	}
	authResp, _ := EncodeTLVs([]TLV{{Type: TLVStatus, Value: []byte("ok")}})
	if err = WriteFrame(conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: TypeAuth, SessionID: sessionID, Seq: 2}, Payload: authResp}); err != nil {
		return err
	}
	open, err := ReadFrame(conn)
	if err != nil {
		return err
	}
	if open.Header.Type != TypeOpenStream {
		return ErrInvalidControlFrame
	}
	if _, err = DecodeOpenRequest(open.Payload); err != nil {
		return err
	}
	data, err := ReadFrame(conn)
	if err != nil {
		return err
	}
	if data.Header.Type != TypeData || string(data.Payload) != "ping" {
		return ErrInvalidControlFrame
	}
	return WriteFrame(conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: TypeData, SessionID: sessionID, StreamID: open.Header.StreamID, Seq: 3}, Payload: []byte("pong")})
}

func runMockATPServerUDP(conn net.Conn, expectToken string) error {
	hello, err := ReadFrame(conn)
	if err != nil {
		return err
	}
	if hello.Header.Type != TypeHello {
		return ErrInvalidControlFrame
	}
	sessionID := uint64(11)
	sid := make([]byte, 8)
	putSessionID(sid, sessionID)
	helloResp, _ := EncodeTLVs([]TLV{{Type: TLVSessionID, Value: sid}, {Type: TLVServerNonce, Value: []byte("nonce")}})
	if err = WriteFrame(conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: TypeHello, SessionID: sessionID, Seq: 1}, Payload: helloResp}); err != nil {
		return err
	}
	auth, err := ReadFrame(conn)
	if err != nil {
		return err
	}
	authMap, err := ParseTLVMap(auth.Payload)
	if err != nil {
		return err
	}
	if string(authMap[TLVAuthToken]) != expectToken || string(authMap[TLVAuthPassword]) != "secret" {
		return ErrInvalidControlFrame
	}
	authResp, _ := EncodeTLVs([]TLV{{Type: TLVStatus, Value: []byte("ok")}})
	if err = WriteFrame(conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: TypeAuth, SessionID: sessionID, Seq: 2}, Payload: authResp}); err != nil {
		return err
	}
	open, err := ReadFrame(conn)
	if err != nil {
		return err
	}
	if open.Header.Type != TypeOpenStream {
		return ErrInvalidControlFrame
	}
	if _, err = DecodeOpenRequest(open.Payload); err != nil {
		return err
	}
	dgram, err := ReadFrame(conn)
	if err != nil {
		return err
	}
	if dgram.Header.Type != TypeDatagram || string(dgram.Payload) != "hello" {
		return ErrInvalidControlFrame
	}
	return WriteFrame(conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: TypeDatagram, SessionID: sessionID, StreamID: open.Header.StreamID, Seq: 3}, Payload: []byte("world")})
}

func runMockATPResumeAcceptedServer(conn net.Conn, expectTicket string) error {
	hello, err := ReadFrame(conn)
	if err != nil {
		return err
	}
	if hello.Header.Type != TypeHello {
		return ErrInvalidControlFrame
	}
	helloMap, err := ParseTLVMap(hello.Payload)
	if err != nil {
		return err
	}
	if string(helloMap[TLVResumeReq]) != expectTicket {
		return ErrInvalidControlFrame
	}
	sessionID := uint64(20)
	sid := make([]byte, 8)
	putSessionID(sid, sessionID)
	helloResp, _ := EncodeTLVs([]TLV{{Type: TLVSessionID, Value: sid}, {Type: TLVServerNonce, Value: []byte("nonce")}, {Type: TLVResumeAccept, Value: []byte{1}}})
	if err = WriteFrame(conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: TypeHello, SessionID: sessionID, Seq: 1}, Payload: helloResp}); err != nil {
		return err
	}
	authResp, _ := EncodeTLVs([]TLV{{Type: TLVStatus, Value: []byte("ok")}, {Type: TLVResumeTicket, Value: []byte("resume-next")}})
	if err = WriteFrame(conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: TypeAuth, SessionID: sessionID, Seq: 2}, Payload: authResp}); err != nil {
		return err
	}
	_, _ = ReadFrame(conn)
	return nil
}

func runMockATPResumeFallbackServer(conn net.Conn, expectToken string) error {
	hello, err := ReadFrame(conn)
	if err != nil {
		return err
	}
	if hello.Header.Type != TypeHello {
		return ErrInvalidControlFrame
	}
	helloMap, err := ParseTLVMap(hello.Payload)
	if err != nil {
		return err
	}
	if string(helloMap[TLVResumeReq]) != "resume-old" {
		return ErrInvalidControlFrame
	}
	sessionID := uint64(21)
	sid := make([]byte, 8)
	putSessionID(sid, sessionID)
	helloResp, _ := EncodeTLVs([]TLV{{Type: TLVSessionID, Value: sid}, {Type: TLVServerNonce, Value: []byte("nonce")}, {Type: TLVResumeAccept, Value: []byte{0}}})
	if err = WriteFrame(conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: TypeHello, SessionID: sessionID, Seq: 1}, Payload: helloResp}); err != nil {
		return err
	}
	auth, err := ReadFrame(conn)
	if err != nil {
		return err
	}
	authMap, err := ParseTLVMap(auth.Payload)
	if err != nil {
		return err
	}
	if string(authMap[TLVAuthToken]) != expectToken || string(authMap[TLVAuthPassword]) != "secret" {
		return ErrInvalidControlFrame
	}
	authResp, _ := EncodeTLVs([]TLV{{Type: TLVStatus, Value: []byte("ok")}, {Type: TLVResumeTicket, Value: []byte("resume-fallback-next")}})
	if err = WriteFrame(conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: TypeAuth, SessionID: sessionID, Seq: 2}, Payload: authResp}); err != nil {
		return err
	}
	_, _ = ReadFrame(conn)
	return nil
}

func putSessionID(dst []byte, id uint64) {
	dst[0] = byte(id >> 56)
	dst[1] = byte(id >> 48)
	dst[2] = byte(id >> 40)
	dst[3] = byte(id >> 32)
	dst[4] = byte(id >> 24)
	dst[5] = byte(id >> 16)
	dst[6] = byte(id >> 8)
	dst[7] = byte(id)
}
