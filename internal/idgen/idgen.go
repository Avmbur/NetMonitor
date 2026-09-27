package idgen

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"
)

var seq atomic.Uint64

func NewV7() string {
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(b[0:8], ms<<16)
	if _, err := rand.Read(b[6:]); err != nil {
		panic(err)
	}
	n := seq.Add(1)
	binary.BigEndian.PutUint16(b[6:8], uint16(n))
	b[6] = (b[6] & 0x0f) | 0x70
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func Token() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func SHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TokenHash(token string) string {
	return SHA256Hex([]byte(token))
}
