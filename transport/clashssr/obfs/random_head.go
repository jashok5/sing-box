package obfs

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash/crc32"
	mrand "math/rand"
	"net"

	"github.com/Dreamacro/clash/common/pool"
)

const maxRandomHeadPendingBuffer = 256 * 1024

var errRandomHeadBufferOverflow = errors.New("random_head buffered data too large before handshake")

func init() {
	register("random_head", newRandomHead, 0)
}

type randomHead struct {
	*Base
}

func newRandomHead(b *Base) Obfs {
	return &randomHead{Base: b}
}

type randomHeadConn struct {
	net.Conn
	*randomHead
	hasSentHeader bool
	rawTransSent  bool
	rawTransRecv  bool
	buf           []byte
}

func (r *randomHead) StreamConn(c net.Conn) net.Conn {
	return &randomHeadConn{Conn: c, randomHead: r}
}

func (c *randomHeadConn) Read(b []byte) (int, error) {
	if c.rawTransRecv {
		return c.Conn.Read(b)
	}
	buf := pool.Get(pool.RelayBufferSize)
	defer pool.Put(buf)
	_, err := c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}
	c.rawTransRecv = true
	if _, err = c.Write(nil); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *randomHeadConn) Write(b []byte) (int, error) {
	if c.rawTransSent {
		return c.Conn.Write(b)
	}
	if len(b) > 0 {
		currentLength := len(c.buf)
		if currentLength+len(b) > maxRandomHeadPendingBuffer {
			return 0, errRandomHeadBufferOverflow
		}
		if cap(c.buf) < currentLength+len(b) {
			reserve := currentLength + len(b)
			if reserve < 4096 {
				reserve = 4096
			}
			next := make([]byte, currentLength, reserve)
			copy(next, c.buf)
			c.buf = next
		}
		c.buf = append(c.buf, b...)
	}
	if !c.hasSentHeader {
		c.hasSentHeader = true
		dataLength := mrand.Intn(96) + 4
		buf := pool.Get(dataLength + 4)
		defer pool.Put(buf)
		rand.Read(buf[:dataLength])
		binary.LittleEndian.PutUint32(buf[dataLength:], 0xffffffff-crc32.ChecksumIEEE(buf[:dataLength]))
		_, err := c.Conn.Write(buf)
		return len(b), err
	}
	if c.rawTransRecv {
		_, err := c.Conn.Write(c.buf)
		c.buf = nil
		c.rawTransSent = true
		return len(b), err
	}
	return len(b), nil
}
