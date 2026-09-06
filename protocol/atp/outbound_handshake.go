package atp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
	E "github.com/sagernet/sing/common/exceptions"
)

func (o *Outbound) newSessionConn(ctx context.Context, resumeTicket string) (*sessionConn, string, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	if o.transport == "quic" {
		return o.newQUICSessionConn(ctx, resumeTicket)
	}
	var (
		rawConn net.Conn
		err     error
	)
	if o.transport == "tls" {
		rawConn, err = o.tlsDialer.DialTLSContext(ctx, o.serverAddr)
		if err != nil {
			return nil, "", err
		}
	} else {
		rawConn, err = o.dialer.DialContext(ctx, N.NetworkTCP, o.serverAddr)
		if err != nil {
			return nil, "", err
		}
	}
	if err = rawConn.SetDeadline(time.Now().Add(o.handshakeTimeout)); err != nil {
		_ = rawConn.Close()
		return nil, "", err
	}
	link, newTicket, err := clientHandshake(rawConn, o.clientName, o.token, o.password, resumeTicket, o.transport)
	if err != nil {
		_ = rawConn.Close()
		return nil, "", err
	}
	_ = rawConn.SetDeadline(time.Time{})
	return link, newTicket, nil
}

func (o *Outbound) newSessionConnFromRaw(rawConn net.Conn, resumeTicket string) (*sessionConn, string, error) {
	if err := rawConn.SetDeadline(time.Now().Add(o.handshakeTimeout)); err != nil {
		_ = rawConn.Close()
		return nil, "", err
	}
	link, newTicket, err := clientHandshake(rawConn, o.clientName, o.token, o.password, resumeTicket, o.transport)
	if err != nil {
		_ = rawConn.Close()
		return nil, "", err
	}
	_ = rawConn.SetDeadline(time.Time{})
	return link, newTicket, nil
}

func preferredALPNForTransport(existing []string, transport string) []string {
	preferred := []string{"atp", "h2", "http/1.1"}
	if strings.EqualFold(strings.TrimSpace(transport), "quic") {
		preferred = []string{"atp", "h3"}
	}
	return mergeALPNWithPreference(existing, preferred)
}

func mergeALPNWithPreference(existing []string, preferred []string) []string {
	out := make([]string, 0, len(preferred)+len(existing))
	seen := make(map[string]struct{}, len(preferred)+len(existing))
	for _, proto := range preferred {
		p := strings.TrimSpace(proto)
		if p == "" {
			continue
		}
		k := strings.ToLower(p)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, p)
	}
	for _, proto := range existing {
		p := strings.TrimSpace(proto)
		if p == "" {
			continue
		}
		k := strings.ToLower(p)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, p)
	}
	return out
}

func clientHandshake(conn net.Conn, clientName string, token string, password string, resumeTicket string, transport string) (*sessionConn, string, error) {
	seq := atomic.Uint32{}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	helloItems := []TLV{{Type: TLVClientName, Value: []byte(clientName)}, {Type: TLVClientNonce, Value: nonce}}
	coverAuth, err := EncodeTLVs([]TLV{
		{Type: TLVAuthToken, Value: []byte(token)},
		{Type: TLVAuthPassword, Value: []byte(password)},
		{Type: TLVResumeReq, Value: []byte(resumeTicket)},
	})
	if err != nil {
		return nil, "", err
	}
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))
	randBytes := make([]byte, 16)
	if _, err = rand.Read(randBytes); err != nil {
		return nil, "", err
	}
	pad := make([]byte, 32)
	if _, err = rand.Read(pad); err != nil {
		return nil, "", err
	}
	helloItems = append(helloItems,
		TLV{Type: TLVCoverMode, Value: []byte(coverModeByTransport(transport))},
		TLV{Type: TLVCoverTS, Value: ts},
		TLV{Type: TLVCoverRandom, Value: randBytes},
		TLV{Type: TLVCoverPadding, Value: pad},
		TLV{Type: TLVCoverToken, Value: coverAuth},
	)
	helloPayload, err := EncodeTLVs(helloItems)
	if err != nil {
		return nil, "", err
	}
	if err = WriteFrame(conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: TypeHello, Seq: seq.Add(1)}, Payload: helloPayload}); err != nil {
		return nil, "", err
	}
	helloResp, err := ReadFrame(conn)
	if err != nil {
		return nil, "", err
	}
	if helloResp.Header.Type == TypeError {
		return nil, "", decodeErrorPayload(helloResp.Payload)
	}
	if helloResp.Header.Type != TypeHello {
		return nil, "", E.New("expected HELLO response")
	}
	helloMap, err := ParseTLVMap(helloResp.Payload)
	if err != nil {
		return nil, "", err
	}
	if len(helloMap[TLVCoverToken]) == 0 {
		return nil, "", E.New("missing cover envelope in HELLO")
	}
	helloMap = normalizedHelloTLVMap(helloMap)
	if len(helloMap[TLVSessionID]) != 8 {
		return nil, "", E.New("missing session id")
	}
	sessionID := binary.BigEndian.Uint64(helloMap[TLVSessionID])
	resumed := len(helloMap[TLVResumeAccept]) > 0 && helloMap[TLVResumeAccept][0] == 1
	if !resumed {
		authItems := []TLV{{Type: TLVAuthToken, Value: []byte(token)}}
		if password != "" {
			authItems = append(authItems, TLV{Type: TLVAuthPassword, Value: []byte(password)})
		}
		rawAuthPayload, err := EncodeTLVs(authItems)
		if err != nil {
			return nil, "", err
		}
		authPayload, err := buildCoverEnvelope(coverModeByTransport(transport), rawAuthPayload)
		if err != nil {
			return nil, "", err
		}
		if err = WriteFrame(conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: TypeAuth, SessionID: sessionID, Seq: seq.Add(1)}, Payload: authPayload}); err != nil {
			return nil, "", err
		}
	}
	authResp, err := ReadFrame(conn)
	if err != nil {
		return nil, "", err
	}
	if authResp.Header.Type == TypeError {
		return nil, "", decodeErrorPayload(authResp.Payload)
	}
	if authResp.Header.Type != TypeAuth || authResp.Header.SessionID != sessionID {
		return nil, "", E.New("expected AUTH response")
	}
	authMap, err := ParseTLVMap(authResp.Payload)
	if err != nil {
		return nil, "", err
	}
	if len(authMap[TLVCoverToken]) == 0 {
		return nil, "", E.New("missing cover envelope in AUTH")
	}
	authMap = normalizedAuthTLVMap(authMap)
	if string(authMap[TLVStatus]) != "ok" {
		return nil, "", E.New("auth failed")
	}
	link := &sessionConn{conn: conn, sessionID: sessionID}
	link.seq.Store(seq.Load())
	if err = link.openReader(); err != nil {
		return nil, "", err
	}
	return link, string(authMap[TLVResumeTicket]), nil
}
