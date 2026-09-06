package atp

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type sessionConn struct {
	conn       net.Conn
	sessionID  uint64
	owner      *Outbound
	seq        atomic.Uint32
	writeMu    sync.Mutex
	streamID   atomic.Uint32
	readerMu   sync.Mutex
	streams    map[uint32]*streamState
	closed     atomic.Bool
	lastActive atomic.Int64
	pingMu     sync.Mutex
	pingWait   chan struct{}
	pingNonce  []byte
}

type streamState struct {
	id          uint32
	network     uint8
	destination M.Socksaddr
	readCh      chan []byte
	closeCh     chan struct{}
	closeOnce   sync.Once
}

func (s *sessionConn) openReader() error {
	s.touch()
	go s.readLoop()
	return nil
}

func (s *sessionConn) readLoop() {
	for {
		frame, err := ReadFrame(s.conn)
		if err != nil {
			s.notifyOwnerSessionLost()
			s.closeAllStreams()
			_ = s.close()
			return
		}
		if frame.Header.Type == TypeError {
			s.notifyOwnerSessionLost()
			s.closeAllStreams()
			_ = s.close()
			return
		}
		s.touch()
		if frame.Header.Type == TypePing {
			s.resolvePing(frame.Payload)
			continue
		}
		s.readerMu.Lock()
		st := s.streams[frame.Header.StreamID]
		s.readerMu.Unlock()
		if st == nil {
			continue
		}
		switch frame.Header.Type {
		case TypeData, TypeDatagram:
			payload := append([]byte(nil), frame.Payload...)
			select {
			case st.readCh <- payload:
			case <-st.closeCh:
			}
		case TypeCloseStream:
			s.closeStream(frame.Header.StreamID)
		case TypeCloseSess:
			s.closeAllStreams()
			_ = s.close()
			return
		}
	}
}

func (s *sessionConn) notifyOwnerSessionLost() {
	if s == nil || s.owner == nil {
		return
	}
	o := s.owner
	o.sessionMu.Lock()
	if o.session == s {
		o.session = nil
	}
	o.sessionMu.Unlock()
}

func (s *sessionConn) open(ctx context.Context, network uint8, destination M.Socksaddr) (uint32, *streamState, error) {
	var domain string
	if inbound := adapter.ContextFrom(ctx); inbound != nil {
		domain = strings.TrimSpace(inbound.Domain)
		if domain != "" {
			domain = strings.TrimSuffix(domain, ".")
		}
		if domain == "" && inbound.Destination.IsDomain() {
			domain = strings.TrimSpace(inbound.Destination.Fqdn)
		}
		if domain == "" && inbound.OriginDestination.IsDomain() {
			domain = strings.TrimSpace(inbound.OriginDestination.Fqdn)
		}
	}
	host := destination.AddrString()
	if destination.IsDomain() {
		host = destination.Fqdn
		if domain == "" {
			domain = host
		}
	}
	if host == "" || destination.Port == 0 {
		return 0, nil, os.ErrInvalid
	}
	payload, err := EncodeOpenRequest(OpenRequest{Network: network, Host: host, Port: destination.Port, Domain: domain})
	if err != nil {
		return 0, nil, err
	}
	streamID := s.streamID.Add(2)
	if streamID == 0 {
		streamID = 2
		s.streamID.Store(streamID)
	}
	st := &streamState{id: streamID, network: network, destination: destination, readCh: make(chan []byte, 64), closeCh: make(chan struct{})}
	s.readerMu.Lock()
	if s.closed.Load() {
		s.readerMu.Unlock()
		return 0, nil, net.ErrClosed
	}
	if s.streams == nil {
		s.streams = make(map[uint32]*streamState)
	}
	s.streams[streamID] = st
	s.readerMu.Unlock()
	if err = s.writeFrame(streamID, TypeOpenStream, payload); err != nil {
		s.closeStream(streamID)
		return 0, nil, err
	}
	return streamID, st, nil
}

func (s *sessionConn) writeFrame(streamID uint32, frameType uint8, payload []byte) error {
	if s.closed.Load() {
		return net.ErrClosed
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if payload != nil {
		payload = append([]byte(nil), payload...)
	}
	if err := s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if err := WriteFrame(s.conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: frameType, SessionID: s.sessionID, StreamID: streamID, Seq: s.seq.Add(1)}, Payload: payload}); err != nil {
		s.notifyOwnerSessionLost()
		return err
	}
	_ = s.conn.SetWriteDeadline(time.Time{})
	s.touch()
	return nil
}

func (s *sessionConn) closeStream(streamID uint32) {
	s.readerMu.Lock()
	st := s.streams[streamID]
	if st != nil {
		delete(s.streams, streamID)
	}
	s.readerMu.Unlock()
	if st != nil {
		st.closeOnce.Do(func() {
			close(st.closeCh)
			close(st.readCh)
		})
	}
}

func (s *sessionConn) closeAllStreams() {
	s.readerMu.Lock()
	all := s.streams
	s.streams = nil
	s.readerMu.Unlock()
	for _, st := range all {
		if st == nil {
			continue
		}
		st.closeOnce.Do(func() {
			close(st.closeCh)
			close(st.readCh)
		})
	}
}

func (s *sessionConn) close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.notifyOwnerSessionLost()
	s.closeAllStreams()
	return s.conn.Close()
}

func (s *sessionConn) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

func (s *sessionConn) idleDuration() time.Duration {
	v := s.lastActive.Load()
	if v <= 0 {
		return defaultSessionIdleTimeout
	}
	return time.Since(time.Unix(0, v))
}

func (s *sessionConn) resolvePing(payload []byte) {
	s.pingMu.Lock()
	defer s.pingMu.Unlock()
	if s.pingWait == nil || len(s.pingNonce) == 0 {
		return
	}
	if !bytes.Equal(s.pingNonce, payload) {
		return
	}
	close(s.pingWait)
	s.pingWait = nil
	s.pingNonce = nil
}

func (s *sessionConn) probe(ctx context.Context) error {
	if s.closed.Load() {
		return net.ErrClosed
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ack := make(chan struct{})
	s.pingMu.Lock()
	if s.pingWait != nil {
		s.pingMu.Unlock()
		return nil
	}
	s.pingWait = ack
	s.pingNonce = append([]byte(nil), nonce...)
	s.pingMu.Unlock()

	if err := s.writeFrame(0, TypePing, nonce); err != nil {
		s.pingMu.Lock()
		s.pingWait = nil
		s.pingNonce = nil
		s.pingMu.Unlock()
		return err
	}

	select {
	case <-ctx.Done():
		s.pingMu.Lock()
		s.pingWait = nil
		s.pingNonce = nil
		s.pingMu.Unlock()
		return ctx.Err()
	case <-ack:
		return nil
	}
}
