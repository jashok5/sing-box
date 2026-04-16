package atp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.ATPOutboundOptions](registry, C.TypeATP, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger            log.ContextLogger
	dialer            N.Dialer
	serverAddr        M.Socksaddr
	token             string
	password          string
	clientName        string
	transport         string
	handshakeTimeout  time.Duration
	tlsConfig         tls.Config
	tlsDialer         tls.Dialer
	sessionMu         sync.Mutex
	session           *sessionConn
	resumeTicket      string
	maintenanceCancel context.CancelFunc
}

const (
	defaultSessionIdleTimeout   = 60 * time.Second
	defaultSessionProbeInterval = 20 * time.Second
	defaultSessionProbeTimeout  = 3 * time.Second
)

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ATPOutboundOptions) (adapter.Outbound, error) {
	if options.Token == "" {
		return nil, E.New("atp token is required")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	handshakeTimeout := time.Duration(options.HandshakeTimeout)
	if handshakeTimeout <= 0 {
		handshakeTimeout = 10 * time.Second
	}
	clientName := options.ClientName
	if clientName == "" {
		clientName = "sing-box-atp"
	}
	transport := options.Transport
	if transport == "" {
		transport = options.Protocol
	}
	if transport == "" {
		transport = N.NetworkTCP
	}
	if transport != N.NetworkTCP && transport != "tls" && transport != "quic" {
		return nil, E.New("unknown ATP outbound transport: ", transport)
	}
	var tlsConfig tls.Config
	var tlsDialer tls.Dialer
	if options.TLS != nil && options.TLS.Enabled {
		config, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		tlsConfig = config
		if transport == "tls" || transport == "quic" {
			nextProtos := tlsConfig.NextProtos()
			if !containsALPN(nextProtos, "atp") {
				tlsConfig.SetNextProtos(append([]string{"atp"}, nextProtos...))
			}
		}
		tlsDialer = tls.NewDialer(outboundDialer, tlsConfig)
	}
	if (transport == "tls" || transport == "quic") && tlsConfig == nil {
		return nil, E.New("ATP outbound transport ", transport, " requires tls.enabled=true")
	}
	network := options.Network.Build()
	if len(network) == 0 {
		network = []string{N.NetworkTCP, N.NetworkUDP}
	}
	o := &Outbound{
		Adapter:          outbound.NewAdapterWithDialerOptions(C.TypeATP, tag, network, options.DialerOptions),
		logger:           logger,
		dialer:           outboundDialer,
		serverAddr:       options.ServerOptions.Build(),
		token:            options.Token,
		password:         options.Password,
		clientName:       clientName,
		transport:        transport,
		handshakeTimeout: handshakeTimeout,
		tlsConfig:        tlsConfig,
		tlsDialer:        tlsDialer,
	}
	maintainCtx, cancel := context.WithCancel(ctx)
	o.maintenanceCancel = cancel
	go o.maintainSessionLoop(maintainCtx)
	return o, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP {
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	link, streamID, streamState, err := o.openStreamWithRetry(ctx, NetworkTCP, destination)
	if err != nil {
		return nil, err
	}
	o.logger.InfoContext(ctx, "ATP outbound TCP to ", destination)
	return newOutboundStreamConn(link, streamID, streamState), nil
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	link, streamID, streamState, err := o.openStreamWithRetry(ctx, NetworkUDP, destination)
	if err != nil {
		return nil, err
	}
	o.logger.InfoContext(ctx, "ATP outbound UDP to ", destination)
	return newOutboundPacketConn(link, streamID, streamState), nil
}

func (o *Outbound) InterfaceUpdated() {}

func (o *Outbound) Close() error {
	if o.maintenanceCancel != nil {
		o.maintenanceCancel()
	}
	o.sessionMu.Lock()
	link := o.session
	o.session = nil
	o.sessionMu.Unlock()
	if link != nil {
		return link.close()
	}
	return nil
}

func (o *Outbound) openStreamWithRetry(ctx context.Context, network uint8, destination M.Socksaddr) (*sessionConn, uint32, *streamState, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		link, err := o.getOrCreateSession(ctx)
		if err != nil {
			lastErr = err
			continue
		}
		streamID, st, err := link.open(ctx, network, destination)
		if err == nil {
			return link, streamID, st, nil
		}
		lastErr = err
		o.invalidateSession(link)
	}
	if lastErr != nil {
		return nil, 0, nil, lastErr
	}
	return nil, 0, nil, net.ErrClosed
}

func (o *Outbound) getOrCreateSession(ctx context.Context) (*sessionConn, error) {
	o.sessionMu.Lock()
	defer o.sessionMu.Unlock()
	if o.session != nil && !o.session.closed.Load() {
		return o.session, nil
	}
	resumeCandidate := o.resumeTicket
	link, resumeTicket, err := o.newSessionConn(ctx, resumeCandidate)
	if err != nil && resumeCandidate != "" {
		o.resumeTicket = ""
		link, resumeTicket, err = o.newSessionConn(ctx, "")
	}
	if err != nil {
		return nil, err
	}
	if resumeTicket != "" {
		o.resumeTicket = resumeTicket
	}
	o.session = link
	return link, nil
}

func (o *Outbound) invalidateSession(link *sessionConn) {
	if link == nil {
		return
	}
	o.sessionMu.Lock()
	if o.session == link {
		o.session = nil
	}
	o.sessionMu.Unlock()
	_ = link.close()
}

func (o *Outbound) maintainSessionLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			link := o.currentSession()
			if link == nil {
				continue
			}
			idle := link.idleDuration()
			if idle >= defaultSessionIdleTimeout {
				o.logger.DebugContext(ctx, "ATP session closed by idle timeout", "idle", idle.String())
				o.invalidateSession(link)
				continue
			}
			if idle >= defaultSessionProbeInterval {
				probeCtx, cancel := context.WithTimeout(ctx, defaultSessionProbeTimeout)
				err := link.probe(probeCtx)
				cancel()
				if err != nil {
					o.logger.DebugContext(ctx, "ATP session health probe failed", "error", err.Error())
					o.invalidateSession(link)
				}
			}
		}
	}
}

func (o *Outbound) currentSession() *sessionConn {
	o.sessionMu.Lock()
	defer o.sessionMu.Unlock()
	if o.session == nil || o.session.closed.Load() {
		return nil
	}
	return o.session
}

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
	link, newTicket, err := clientHandshake(rawConn, o.clientName, o.token, o.password, resumeTicket)
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
	link, newTicket, err := clientHandshake(rawConn, o.clientName, o.token, o.password, resumeTicket)
	if err != nil {
		_ = rawConn.Close()
		return nil, "", err
	}
	_ = rawConn.SetDeadline(time.Time{})
	return link, newTicket, nil
}

func containsALPN(items []string, target string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), target) {
			return true
		}
	}
	return false
}

func clientHandshake(conn net.Conn, clientName string, token string, password string, resumeTicket string) (*sessionConn, string, error) {
	seq := atomic.Uint32{}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	helloItems := []TLV{{Type: TLVClientName, Value: []byte(clientName)}, {Type: TLVClientNonce, Value: nonce}}
	if resumeTicket != "" {
		helloItems = append(helloItems, TLV{Type: TLVResumeReq, Value: []byte(resumeTicket)})
	}
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
		authPayload, err := EncodeTLVs(authItems)
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

type sessionConn struct {
	conn       net.Conn
	sessionID  uint64
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
			s.closeAllStreams()
			_ = s.close()
			return
		}
		if frame.Header.Type == TypeError {
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
	if err := WriteFrame(s.conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: frameType, SessionID: s.sessionID, StreamID: streamID, Seq: s.seq.Add(1)}, Payload: payload}); err != nil {
		return err
	}
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

type outboundStreamConn struct {
	s        *sessionConn
	streamID uint32
	st       *streamState
	readBuf  []byte
}

func newOutboundStreamConn(s *sessionConn, streamID uint32, st *streamState) *outboundStreamConn {
	return &outboundStreamConn{s: s, streamID: streamID, st: st}
}

func (c *outboundStreamConn) Read(p []byte) (int, error) {
	if c.st == nil {
		return 0, io.EOF
	}
	for len(c.readBuf) == 0 {
		select {
		case data, ok := <-c.st.readCh:
			if !ok {
				return 0, io.EOF
			}
			c.readBuf = data
		case <-c.st.closeCh:
			return 0, io.EOF
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *outboundStreamConn) Write(p []byte) (int, error) {
	if c.st == nil {
		return 0, net.ErrClosed
	}
	if err := c.s.writeFrame(c.streamID, TypeData, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *outboundStreamConn) Close() error {
	if c.st != nil {
		done := make(chan struct{}, 1)
		go func() {
			_ = c.s.writeFrame(c.streamID, TypeCloseStream, nil)
			done <- struct{}{}
		}()
		select {
		case <-done:
		case <-time.After(200 * time.Millisecond):
		}
		c.s.closeStream(c.streamID)
		c.st = nil
	}
	return nil
}

func (c *outboundStreamConn) LocalAddr() net.Addr { return c.s.conn.LocalAddr() }

func (c *outboundStreamConn) RemoteAddr() net.Addr { return c.s.conn.RemoteAddr() }

func (c *outboundStreamConn) SetDeadline(t time.Time) error { return nil }

func (c *outboundStreamConn) SetReadDeadline(t time.Time) error { return nil }

func (c *outboundStreamConn) SetWriteDeadline(t time.Time) error { return nil }

type outboundPacketConn struct {
	s        *sessionConn
	streamID uint32
	st       *streamState
}

func newOutboundPacketConn(s *sessionConn, streamID uint32, st *streamState) *outboundPacketConn {
	return &outboundPacketConn{s: s, streamID: streamID, st: st}
}

func (c *outboundPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.st == nil {
		return 0, nil, io.EOF
	}
	select {
	case data, ok := <-c.st.readCh:
		if !ok {
			return 0, nil, io.EOF
		}
		n := copy(p, data)
		if c.st.destination.IsDomain() {
			return n, c.st.destination, nil
		}
		return n, c.st.destination.UDPAddr(), nil
	case <-c.st.closeCh:
		return 0, nil, io.EOF
	}
}

func (c *outboundPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.st == nil {
		return 0, net.ErrClosed
	}
	if err := c.s.writeFrame(c.streamID, TypeDatagram, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *outboundPacketConn) Close() error {
	if c.st != nil {
		done := make(chan struct{}, 1)
		go func() {
			_ = c.s.writeFrame(c.streamID, TypeCloseStream, nil)
			done <- struct{}{}
		}()
		select {
		case <-done:
		case <-time.After(200 * time.Millisecond):
		}
		c.s.closeStream(c.streamID)
		c.st = nil
	}
	return nil
}

func (c *outboundPacketConn) LocalAddr() net.Addr { return c.s.conn.LocalAddr() }

func (c *outboundPacketConn) SetDeadline(t time.Time) error { return nil }

func (c *outboundPacketConn) SetReadDeadline(t time.Time) error { return nil }

func (c *outboundPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *outboundPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if c.st == nil {
		return M.Socksaddr{}, io.EOF
	}
	select {
	case data, ok := <-c.st.readCh:
		if !ok {
			return M.Socksaddr{}, io.EOF
		}
		_, _ = buffer.Write(data)
		return c.st.destination, nil
	case <-c.st.closeCh:
		return M.Socksaddr{}, io.EOF
	}
}

func (c *outboundPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if c.st == nil {
		return net.ErrClosed
	}
	return c.s.writeFrame(c.streamID, TypeDatagram, buffer.Bytes())
}

func (c *outboundPacketConn) FrontHeadroom() int {
	return 0
}

func (c *outboundPacketConn) NeedAdditionalReadDeadline() bool {
	return false
}

func parseDestination(addr string) M.Socksaddr {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return M.Socksaddr{}
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	portNum, err := net.LookupPort("tcp", port)
	if err != nil {
		return M.Socksaddr{}
	}
	return M.ParseSocksaddrHostPort(host, uint16(portNum))
}
