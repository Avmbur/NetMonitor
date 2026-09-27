package passwd

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

func Hash(plain string) (string, error) {
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", err
	}
	sum := sha256.Sum256(append(salt[:], []byte(plain)...))
	return fmt.Sprintf("s256$%s$%s", hex.EncodeToString(salt[:]), hex.EncodeToString(sum[:])), nil
}

func Check(hash, plain string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 3 || parts[0] != "s256" {
		return false
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sum := sha256.Sum256(append(salt, []byte(plain)...))
	return subtle.ConstantTimeCompare(sum[:], want) == 1
}
