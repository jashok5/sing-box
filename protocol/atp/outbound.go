package atp

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	E "github.com/sagernet/sing/common/exceptions"
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
	defaultSessionIdleTimeout   = 20 * time.Second
	defaultSessionProbeInterval = 6 * time.Second
	defaultSessionProbeTimeout  = 2 * time.Second
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
			tlsConfig.SetNextProtos(preferredALPNForTransport(tlsConfig.NextProtos(), transport))
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
	link.owner = o
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
	ticker := time.NewTicker(3 * time.Second)
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
