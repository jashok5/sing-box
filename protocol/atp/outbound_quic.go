//go:build with_quic

package atp

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/quic-go"
	sQUIC "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

func (o *Outbound) newQUICSessionConn(ctx context.Context, resumeTicket string) (*sessionConn, string, error) {
	udpConn, err := o.dialer.DialContext(ctx, N.NetworkUDP, o.serverAddr)
	if err != nil {
		return nil, "", err
	}
	quicConn, err := sQUIC.DialEarly(ctx, bufio.NewUnbindPacketConn(udpConn), o.serverAddr.UDPAddr(), o.tlsConfig, nil)
	if err != nil {
		_ = udpConn.Close()
		return nil, "", err
	}
	stream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		_ = quicConn.CloseWithError(0, "")
		return nil, "", err
	}
	return o.newSessionConnFromRaw(&quicStreamWrapper{Conn: quicConn, Stream: stream}, resumeTicket)
}

type quicStreamWrapper struct {
	Conn *quic.Conn
	*quic.Stream
}

func (s *quicStreamWrapper) LocalAddr() net.Addr {
	return s.Conn.LocalAddr()
}

func (s *quicStreamWrapper) RemoteAddr() net.Addr {
	return s.Conn.RemoteAddr()
}

func (s *quicStreamWrapper) Close() error {
	s.CancelRead(0)
	_ = s.Stream.Close()
	return s.Conn.CloseWithError(0, "")
}

func (s *quicStreamWrapper) SetDeadline(t time.Time) error {
	return s.Stream.SetDeadline(t)
}

func (s *quicStreamWrapper) SetReadDeadline(t time.Time) error {
	return s.Stream.SetReadDeadline(t)
}

func (s *quicStreamWrapper) SetWriteDeadline(t time.Time) error {
	return s.Stream.SetWriteDeadline(t)
}
