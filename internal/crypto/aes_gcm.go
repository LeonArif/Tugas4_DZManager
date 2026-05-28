package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

const aesKeyLen = 16	// AES-128 membutuhkan key sepanjang 16 byte.

// mengenkripsi pake AES-128-GCM
func EncryptAESGCM(key []byte, plaintext []byte) (ciphertext []byte, nonce []byte, err error) {
	if len(key) != aesKeyLen {
		return nil, nil, fmt.Errorf("invalid key length: expected %d bytes", aesKeyLen)
	}

	block, err := aes.NewCipher(key)	// membuat blok cipher AES dari key
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)	// membuat mode GCM di atas AES
	if err != nil {
		return nil, nil, fmt.Errorf("create gcm: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// mendekripsi pake AES-128-GCM
func DecryptAESGCM(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != aesKeyLen {
		return nil, fmt.Errorf("invalid key length: expected %d bytes", aesKeyLen)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length: expected %d bytes", gcm.NonceSize())
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: authentication failed: %w", err)
	}

	return plaintext, nil
}
