package atp

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type sessionWriter struct {
	mu        sync.Mutex
	conn      net.Conn
	sessionID uint64
	seq       atomic.Uint32
}

func (w *sessionWriter) write(streamID uint32, frameType uint8, payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if payload != nil {
		payload = append([]byte(nil), payload...)
	}
	return WriteFrame(w.conn, &Frame{Header: Header{Magic: Magic, Version: VersionV1, Type: frameType, SessionID: w.sessionID, StreamID: streamID, Seq: w.seq.Add(1)}, Payload: payload})
}

type streamEndpoint interface {
	Push(frame *Frame)
	Close() error
}

type atpStreamConn struct {
	streamID uint32
	conn     net.Conn
	writer   *sessionWriter
	readCh   chan []byte
	closeCh  chan struct{}
	closeMux sync.Once
	readBuf  []byte
}

func newATPStreamConn(streamID uint32, conn net.Conn, writer *sessionWriter) *atpStreamConn {
	return &atpStreamConn{streamID: streamID, conn: conn, writer: writer, readCh: make(chan []byte, 16), closeCh: make(chan struct{})}
}

func (c *atpStreamConn) Push(frame *Frame) {
	if frame.Header.Type != TypeData {
		return
	}
	data := append([]byte(nil), frame.Payload...)
	select {
	case c.readCh <- data:
	case <-c.closeCh:
	}
}

func (c *atpStreamConn) Read(p []byte) (int, error) {
	for len(c.readBuf) == 0 {
		select {
		case data, ok := <-c.readCh:
			if !ok {
				return 0, io.EOF
			}
			c.readBuf = data
		case <-c.closeCh:
			return 0, io.EOF
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *atpStreamConn) Write(p []byte) (int, error) {
	if err := c.writer.write(c.streamID, TypeData, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *atpStreamConn) Close() error {
	c.closeMux.Do(func() {
		_ = c.writer.write(c.streamID, TypeCloseStream, nil)
		close(c.closeCh)
		close(c.readCh)
	})
	return nil
}

func (c *atpStreamConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *atpStreamConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *atpStreamConn) SetDeadline(t time.Time) error { return nil }

func (c *atpStreamConn) SetReadDeadline(t time.Time) error { return nil }

func (c *atpStreamConn) SetWriteDeadline(t time.Time) error { return nil }

type atpDatagramConn struct {
	streamID    uint32
	destination M.Socksaddr
	conn        net.Conn
	writer      *sessionWriter
	readCh      chan []byte
	closeCh     chan struct{}
	closeMux    sync.Once
}

func newATPDatagramConn(streamID uint32, destination M.Socksaddr, writer *sessionWriter) *atpDatagramConn {
	return &atpDatagramConn{streamID: streamID, destination: destination, conn: writer.conn, writer: writer, readCh: make(chan []byte, 64), closeCh: make(chan struct{})}
}

func (c *atpDatagramConn) Push(frame *Frame) {
	if frame.Header.Type != TypeDatagram {
		return
	}
	data := append([]byte(nil), frame.Payload...)
	select {
	case c.readCh <- data:
	case <-c.closeCh:
	}
}

func (c *atpDatagramConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case data, ok := <-c.readCh:
		if !ok {
			return M.Socksaddr{}, io.EOF
		}
		_, _ = buffer.Write(data)
		return c.destination, nil
	case <-c.closeCh:
		return M.Socksaddr{}, io.EOF
	}
}

func (c *atpDatagramConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	return c.writer.write(c.streamID, TypeDatagram, buffer.Bytes())
}

func (c *atpDatagramConn) Close() error {
	c.closeMux.Do(func() {
		_ = c.writer.write(c.streamID, TypeCloseStream, nil)
		close(c.closeCh)
		close(c.readCh)
	})
	return nil
}

func (c *atpDatagramConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *atpDatagramConn) SetDeadline(t time.Time) error { return nil }

func (c *atpDatagramConn) SetReadDeadline(t time.Time) error { return nil }

func (c *atpDatagramConn) SetWriteDeadline(t time.Time) error { return nil }
