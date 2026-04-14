//go:build with_quic

package atp

import (
	"context"
	"net"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	qtls "github.com/sagernet/sing-quic"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (h *Inbound) startQUIC() error {
	udpConn, err := h.listener.ListenUDP()
	if err != nil {
		return err
	}
	quicListener, err := qtls.Listen(udpConn, h.tlsConfig, &quic.Config{})
	if err != nil {
		return err
	}
	h.quicServer = quicListener
	go h.acceptQUICLoop(quicListener)
	h.logger.Info("atp quic server started at ", udpConn.LocalAddr())
	return nil
}

func (h *Inbound) acceptQUICLoop(listener qtls.Listener) {
	for {
		conn, err := listener.Accept(h.ctx)
		if err != nil {
			return
		}
		go h.serveQUICConn(conn)
	}
}

func (h *Inbound) serveQUICConn(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			wrapped := &quicStreamConn{Conn: conn, Stream: stream}
			metadataIn := adapter.InboundContext{
				Source:            M.SocksaddrFromNet(conn.RemoteAddr()),
				OriginDestination: M.SocksaddrFromNet(conn.LocalAddr()),
				Network:           N.NetworkTCP,
			}
			h.NewConnectionEx(conn.Context(), wrapped, metadataIn, nil)
		}()
	}
}

type quicStreamConn struct {
	Conn *quic.Conn
	*quic.Stream
}

func (s *quicStreamConn) LocalAddr() net.Addr {
	return s.Conn.LocalAddr()
}

func (s *quicStreamConn) RemoteAddr() net.Addr {
	return s.Conn.RemoteAddr()
}

func (s *quicStreamConn) Close() error {
	s.CancelRead(0)
	_ = s.Stream.Close()
	return nil
}
