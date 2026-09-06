package atp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.ATPInboundOptions](registry, C.TypeATP, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	ctx              context.Context
	router           adapter.ConnectionRouterEx
	logger           log.ContextLogger
	listener         *listener.Listener
	tlsConfig        tls.ServerConfig
	quicServer       io.Closer
	transport        string
	tokenMap         map[string]string
	password         string
	handshakeTimeout time.Duration
	idleTimeout      time.Duration
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ATPInboundOptions) (adapter.Inbound, error) {
	tokenMap := make(map[string]string)
	if options.Token != "" {
		tokenMap[options.Token] = ""
	}
	for _, user := range options.Users {
		if user.Token == "" {
			continue
		}
		tokenMap[user.Token] = user.Name
	}
	transport := options.Transport
	if transport == "" {
		transport = N.NetworkTCP
	}
	if transport != N.NetworkTCP && transport != "tls" && transport != "quic" {
		return nil, E.New("unknown ATP inbound transport: ", transport)
	}
	h := &Inbound{
		Adapter:          inbound.NewAdapter(C.TypeATP, tag),
		ctx:              ctx,
		router:           router,
		logger:           logger,
		transport:        transport,
		tokenMap:         tokenMap,
		password:         options.Password,
		handshakeTimeout: time.Duration(options.HandshakeTimeout),
		idleTimeout:      time.Duration(options.IdleTimeout),
	}
	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		h.tlsConfig = tlsConfig
	}
	if (transport == "tls" || transport == "quic") && h.tlsConfig == nil {
		return nil, E.New("ATP inbound transport ", transport, " requires tls.enabled=true")
	}
	if h.handshakeTimeout <= 0 {
		h.handshakeTimeout = 10 * time.Second
	}
	if h.idleTimeout <= 0 {
		h.idleTimeout = 120 * time.Second
	}
	network := []string{N.NetworkTCP}
	if transport == "quic" {
		network = []string{N.NetworkUDP}
	}
	h.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           network,
		Listen:            options.ListenOptions,
		ConnectionHandler: h,
	})
	return h, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		if err := h.tlsConfig.Start(); err != nil {
			return err
		}
	}
	if h.transport == "quic" {
		return h.startQUIC()
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return common.Close(h.listener, h.tlsConfig, h.quicServer)
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	h.NewConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.transport == "tls" {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			if !E.IsClosedOrCanceled(err) {
				h.logger.ErrorContext(ctx, E.Cause(err, "process ATP TLS handshake from ", metadata.Source))
			}
			return
		}
		conn = tlsConn
	}
	_ = conn.SetDeadline(time.Now().Add(h.handshakeTimeout))
	sessionID, user, err := h.serverHandshake(ctx, conn)
	if err != nil {
		_ = h.writeErrorFrame(conn, 0, 1, CodeAuthFailed, err.Error())
		N.CloseOnHandshakeFailure(conn, onClose, err)
		if !E.IsClosedOrCanceled(err) {
			h.logger.ErrorContext(ctx, E.Cause(err, "process ATP handshake from ", metadata.Source))
		}
		return
	}
	_ = conn.SetDeadline(time.Time{})
	h.logger.InfoContext(ctx, "ATP handshake success, session=", sessionID)
	if err := h.serveSession(ctx, conn, sessionID, metadata, user, onClose); err != nil && !E.IsClosedOrCanceled(err) {
		h.logger.ErrorContext(ctx, E.Cause(err, "process ATP session from ", metadata.Source))
	}
}

func (h *Inbound) serverHandshake(ctx context.Context, conn net.Conn) (uint64, string, error) {
	clientHello, err := ReadFrame(conn)
	if err != nil {
		return 0, "", err
	}
	if clientHello.Header.Type != TypeHello {
		return 0, "", h.writeAndReturnError(conn, 0, 1, CodeInvalidFrame, "expected HELLO")
	}
	helloMap, err := ParseTLVMap(clientHello.Payload)
	if err != nil {
		return 0, "", err
	}
	if len(helloMap[TLVCoverToken]) == 0 {
		return 0, "", h.writeAndReturnError(conn, 0, 1, CodeBadRequest, "missing cover envelope")
	}
	helloMap = unwrapCoverTokenMap(helloMap, TLVAuthToken, TLVAuthPassword, TLVResumeReq)
	if len(helloMap[TLVClientNonce]) == 0 {
		return 0, "", h.writeAndReturnError(conn, 0, 1, CodeBadRequest, "missing client nonce")
	}

	sessionID, err := newSessionID()
	if err != nil {
		return 0, "", err
	}
	serverNonce := make([]byte, 16)
	if _, err = rand.Read(serverNonce); err != nil {
		return 0, "", err
	}
	sessionBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(sessionBytes, sessionID)
	coverHelloPayload, err := EncodeTLVs([]TLV{{Type: TLVSessionID, Value: sessionBytes}, {Type: TLVServerNonce, Value: serverNonce}})
	if err != nil {
		return 0, "", err
	}
	helloPayload, err := buildCoverEnvelope(coverModeByTransport(h.transport), coverHelloPayload)
	if err != nil {
		return 0, "", err
	}
	if err = WriteFrame(conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: TypeHello, SessionID: sessionID, Seq: 1}, Payload: helloPayload}); err != nil {
		return 0, "", err
	}

	authFrame, err := ReadFrame(conn)
	if err != nil {
		return 0, "", err
	}
	if authFrame.Header.Type != TypeAuth || authFrame.Header.SessionID != sessionID {
		return 0, "", h.writeAndReturnError(conn, sessionID, 2, CodeInvalidFrame, "expected AUTH")
	}
	authMap, err := ParseTLVMap(authFrame.Payload)
	if err != nil {
		return 0, "", err
	}
	if len(authMap[TLVCoverToken]) == 0 {
		return 0, "", h.writeAndReturnError(conn, sessionID, 2, CodeBadRequest, "missing auth cover envelope")
	}
	authMap = unwrapCoverTokenMap(authMap, TLVAuthToken, TLVAuthPassword)
	token := string(authMap[TLVAuthToken])
	user, ok := h.tokenMap[token]
	if !ok {
		return 0, "", h.writeAndReturnError(conn, sessionID, 2, CodeAuthFailed, "auth failed")
	}
	if h.password != "" {
		if string(authMap[TLVAuthPassword]) != h.password {
			return 0, "", h.writeAndReturnError(conn, sessionID, 2, CodeAuthFailed, "auth password mismatch")
		}
	}
	coverStatusPayload, err := EncodeTLVs([]TLV{{Type: TLVStatus, Value: []byte("ok")}})
	if err != nil {
		return 0, "", err
	}
	statusPayload, err := buildCoverEnvelope(coverModeByTransport(h.transport), coverStatusPayload)
	if err != nil {
		return 0, "", err
	}
	if err = WriteFrame(conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: TypeAuth, SessionID: sessionID, Seq: 2}, Payload: statusPayload}); err != nil {
		return 0, "", err
	}
	return sessionID, user, nil
}

func (h *Inbound) serveSession(ctx context.Context, conn net.Conn, sessionID uint64, baseMetadata adapter.InboundContext, user string, onClose N.CloseHandlerFunc) error {
	w := &sessionWriter{conn: conn, sessionID: sessionID}
	streams := make(map[uint32]streamEndpoint)
	defer func() {
		for _, s := range streams {
			_ = s.Close()
		}
		_ = conn.Close()
	}()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(h.idleTimeout))
		frame, err := ReadFrame(conn)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				_ = h.writeErrorFrame(conn, sessionID, 0, CodeTimeout, "idle timeout")
			}
			return err
		}
		if frame.Header.SessionID != sessionID {
			return E.New("session mismatch")
		}
		switch frame.Header.Type {
		case TypeOpenStream:
			req, err := DecodeOpenRequest(frame.Payload)
			if err != nil {
				_ = h.writeErrorFrame(conn, sessionID, frame.Header.Seq, CodeInvalidFrame, "invalid open stream payload")
				return err
			}
			destination := M.ParseSocksaddrHostPort(req.Host, req.Port)
			if !destination.IsValid() {
				_ = h.writeErrorFrame(conn, sessionID, frame.Header.Seq, CodeBadRequest, "invalid destination")
				return E.New("invalid destination")
			}
			metadata := baseMetadata
			metadata.Inbound = h.Tag()
			metadata.InboundType = h.Type()
			metadata.Destination = destination
			if user != "" {
				metadata.User = user
			}
			streamCtx := log.ContextWithNewID(ctx)
			if req.Network == NetworkUDP {
				pc := newATPDatagramConn(frame.Header.StreamID, destination, w)
				streams[frame.Header.StreamID] = pc
				h.router.RoutePacketConnectionEx(streamCtx, pc, metadata, onClose)
				h.logger.InfoContext(streamCtx, "ATP inbound UDP to ", destination)
			} else {
				tc := newATPStreamConn(frame.Header.StreamID, conn, w)
				streams[frame.Header.StreamID] = tc
				h.router.RouteConnectionEx(streamCtx, tc, metadata, onClose)
				h.logger.InfoContext(streamCtx, "ATP inbound TCP to ", destination)
			}
		case TypeData, TypeDatagram:
			s, ok := streams[frame.Header.StreamID]
			if !ok {
				continue
			}
			s.Push(frame)
		case TypeCloseStream:
			s, ok := streams[frame.Header.StreamID]
			if ok {
				delete(streams, frame.Header.StreamID)
			}
			if ok {
				_ = s.Close()
			}
		case TypeCloseSess:
			return nil
		case TypePing:
			_ = w.write(0, TypePing, frame.Payload)
		case TypeError:
			return decodeErrorPayload(frame.Payload)
		}
	}
}

func (h *Inbound) writeErrorFrame(conn net.Conn, sessionID uint64, seq uint32, code ErrorCode, reason string) error {
	payload, err := encodeErrorPayload(code, reason)
	if err != nil {
		return err
	}
	return WriteFrame(conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: TypeError, SessionID: sessionID, Seq: seq}, Payload: payload})
}

func (h *Inbound) writeAndReturnError(conn net.Conn, sessionID uint64, seq uint32, code ErrorCode, reason string) error {
	_ = h.writeErrorFrame(conn, sessionID, seq, code, reason)
	return E.New(reason)
}

func newSessionID() (uint64, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}
