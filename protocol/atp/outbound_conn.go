package atp

import (
	"io"
	"net"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

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

func (c *outboundPacketConn) FrontHeadroom() int { return 0 }

func (c *outboundPacketConn) NeedAdditionalReadDeadline() bool { return false }
