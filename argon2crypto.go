package argon2crypto

import (
	"crypto/rand"
	"encoding/base64"
	"golang.org/x/crypto/argon2"
)

type params struct {
	memory	    uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func GetHashedPassword(password string, p *params) (encodedHash string, err error) {
	salt, err := generateRandomBytes(p.saltLength)
	if err != nil { return "", err }
	hash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	b64salt := base64.RawStdEncoding.EncodeToString(salt)
	b64hash := base64.RawStdEncoding.EncodeToString(hash)
	encodedHash = string(p.memory) + string(p.iterations) + string(p.parallelism) + b64salt + b64hash
	return encodedHash, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	rawBytes := make([]byte, n)
	_, err := rand.Read(rawBytes)
	if err != nil { return  nil, err }
	return rawBytes, nil
}

func Check(stored, received string) bool {
	return stored == received
}