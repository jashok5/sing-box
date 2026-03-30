package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	mrand "math/rand"
	"sync"
	"time"

	"github.com/Dreamacro/clash/transport/shadowsocks/core"
)

type Base struct {
	Key      []byte
	Overhead int
	Param    string
}

type userData struct {
	userKey []byte
	userID  [4]byte
}

type authData struct {
	clientID     [4]byte
	connectionID uint32
	mutex        sync.Mutex
}

func (a *authData) next() *authData {
	r := &authData{}
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.connectionID > 0xff000000 || a.connectionID == 0 {
		rand.Read(a.clientID[:])
		a.connectionID = mrand.Uint32() & 0xffffff
	}
	a.connectionID++
	copy(r.clientID[:], a.clientID[:])
	r.connectionID = a.connectionID
	return r
}

func (a *authData) putAuthData(buf *bytes.Buffer) {
	var timestampBytes [4]byte
	binary.LittleEndian.PutUint32(timestampBytes[:], uint32(time.Now().Unix()))
	buf.Write(timestampBytes[:])
	buf.Write(a.clientID[:])
	var connectionIDBytes [4]byte
	binary.LittleEndian.PutUint32(connectionIDBytes[:], a.connectionID)
	buf.Write(connectionIDBytes[:])
}

func (a *authData) putEncryptedData(b *bytes.Buffer, userKey []byte, paddings [2]int, salt string) error {
	var encrypt [16]byte
	binary.LittleEndian.PutUint32(encrypt[:4], uint32(time.Now().Unix()))
	copy(encrypt[4:8], a.clientID[:])
	binary.LittleEndian.PutUint32(encrypt[8:12], a.connectionID)
	binary.LittleEndian.PutUint16(encrypt[12:14], uint16(paddings[0]))
	binary.LittleEndian.PutUint16(encrypt[14:16], uint16(paddings[1]))

	cipherKey := core.Kdf(base64.StdEncoding.EncodeToString(userKey)+salt, 16)
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return err
	}
	cbcCipher := cipher.NewCBCEncrypter(block, zeroIV[:])

	cbcCipher.CryptBlocks(encrypt[:], encrypt[:])

	b.Write(encrypt[:])
	return nil
}

var zeroIV [16]byte
