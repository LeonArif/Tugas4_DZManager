package crypto

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/argon2"
)

const minSaltSize = 16

// KDFParams menyimpan parameter Argon2id
type KDFParams struct {
	Time    uint32 // jumlah iterasi komputasi
	Memory  uint32 // penggunaan memori (KB)
	Threads uint8  // jumlah thread paralel
	KeyLen  uint32 // panjang key hasil derivasi
}

func DefaultKDFParams() KDFParams {
	return KDFParams{
		Time:    1,
		Memory:  64 * 1024,
		Threads: 4,
		KeyLen:  16, // 16 byte untuk AES-128
	}
}

// menghasilkan salt random
func GenerateSalt(size int) ([]byte, error) {
	if size < minSaltSize {
		return nil, fmt.Errorf("salt size must be >= %d", minSaltSize)
	}

	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// menurunkan key AES dari master password menggunakan Argon2id
func DeriveKey(masterPassword string, salt []byte) ([]byte, error) {
	if len(salt) < minSaltSize {
		return nil, fmt.Errorf("salt length must be >= %d", minSaltSize)
	}

	params := DefaultKDFParams()
	key := argon2.IDKey([]byte(masterPassword), salt, params.Time, params.Memory, params.Threads, params.KeyLen)
	return key, nil
}
