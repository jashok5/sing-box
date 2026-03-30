package protocol

import (
	"bytes"
	"net"

	"github.com/Dreamacro/clash/common/pool"
)

type Conn struct {
	net.Conn
	Protocol
	decoded      bytes.Buffer
	underDecoded bytes.Buffer
}

func (c *Conn) Read(b []byte) (int, error) {
	for {
		if c.decoded.Len() > 0 {
			return c.decoded.Read(b)
		}

		buf := pool.Get(pool.RelayBufferSize)
		n, err := c.Conn.Read(buf)
		if err != nil {
			pool.Put(buf)
			return 0, err
		}
		c.underDecoded.Write(buf[:n])
		pool.Put(buf)

		err = c.Decode(&c.decoded, &c.underDecoded)
		if err != nil {
			return 0, err
		}
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	bLength := len(b)
	if bLength == 0 {
		return 0, nil
	}
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	err := c.Encode(buf, b)
	if err != nil {
		return 0, err
	}
	_, err = c.Conn.Write(buf.Bytes())
	if err != nil {
		return 0, err
	}
	return bLength, nil
}
