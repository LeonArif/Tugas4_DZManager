package tests

import (
	"bytes"
	"testing"

	"tugas4_dzmanager/internal/crypto"
)

const (
	uppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowercaseLetters = "abcdefghijklmnopqrstuvwxyz"
	digits           = "0123456789"
	symbols          = "!@#$%^&*()-_=+[]{}<>?/|"
)

func TestSplitCombineSecret(t *testing.T) {
	// Uji split+combine dengan 2 dari 3 share (threshold 2, total 3).
	secret := []byte("super-secret")
	shares, err := crypto.SplitSecret(secret, 2, 3)
	if err != nil {
		t.Fatalf("split secret: %v", err)
	}

	recovered, err := crypto.CombineShares([]crypto.Share{shares[0], shares[2]})
	if err != nil {
		t.Fatalf("combine shares: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Fatalf("recovered secret mismatch")
	}
}

func TestCombineSharesInsufficient(t *testing.T) {
	// Uji error ketika jumlah share < threshold.
	secret := []byte("super-secret")
	shares, err := crypto.SplitSecret(secret, 2, 3)
	if err != nil {
		t.Fatalf("split secret: %v", err)
	}

	if _, err := crypto.CombineShares([]crypto.Share{shares[0]}); err == nil {
		t.Fatalf("expected error with insufficient shares")
	}
}

func TestCombineSharesDuplicateShare(t *testing.T) {
	// Uji error ketika ada share dengan X duplikat.
	secret := []byte("super-secret")
	shares, err := crypto.SplitSecret(secret, 2, 3)
	if err != nil {
		t.Fatalf("split secret: %v", err)
	}

	if _, err := crypto.CombineShares([]crypto.Share{shares[0], shares[0]}); err == nil {
		t.Fatalf("expected error with duplicate shares")
	}
}

func TestAESGCMEncryptDecrypt(t *testing.T) {
	// Uji enkripsi dan dekripsi normal harus mengembalikan plaintext yang sama.
	key := []byte("0123456789abcdef")
	plaintext := []byte("vault data")

	ciphertext, nonce, err := crypto.EncryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := crypto.DecryptAESGCM(key, nonce, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestAESGCMInvalidKey(t *testing.T) {
	// Uji dekripsi gagal jika key tidak cocok.
	key := []byte("0123456789abcdef")
	plaintext := []byte("vault data")

	ciphertext, nonce, err := crypto.EncryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	wrongKey := []byte("abcdef0123456789")
	if _, err := crypto.DecryptAESGCM(wrongKey, nonce, ciphertext); err == nil {
		t.Fatalf("expected decrypt error with invalid key")
	}
}

func TestAESGCMModifiedCiphertext(t *testing.T) {
	// Uji autentikasi GCM: ciphertext diubah harus gagal didekripsi.
	key := []byte("0123456789abcdef")
	plaintext := []byte("vault data")

	ciphertext, nonce, err := crypto.EncryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	ciphertext[0] ^= 0x01
	if _, err := crypto.DecryptAESGCM(key, nonce, ciphertext); err == nil {
		t.Fatalf("expected decrypt error for modified ciphertext")
	}
}

func TestGeneratePasswordLength(t *testing.T) {
	// Uji panjang password dan validitas karakter (upper, lower, digit, simbol).
	password, err := crypto.GeneratePassword(12)
	if err != nil {
		t.Fatalf("generate password: %v", err)
	}
	if len(password) != 12 {
		t.Fatalf("unexpected password length: %d", len(password))
	}

	if !containsCharFromSet(password, uppercaseLetters) ||
		!containsCharFromSet(password, lowercaseLetters) ||
		!containsCharFromSet(password, digits) ||
		!containsCharFromSet(password, symbols) {
		t.Fatalf("password does not contain all required character sets")
	}

	allChars := uppercaseLetters + lowercaseLetters + digits + symbols
	if !allCharsInSet(password, allChars) {
		t.Fatalf("password contains invalid characters")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	// Uji deterministik KDF: password + salt sama -> key sama.
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}

	key1, err := crypto.DeriveKey("correct horse battery staple", salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	key2, err := crypto.DeriveKey("correct horse battery staple", salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}

	if len(key1) != 16 {
		t.Fatalf("unexpected key length: %d", len(key1))
	}
	if !bytes.Equal(key1, key2) {
		t.Fatalf("expected deterministic key output")
	}
}

func containsCharFromSet(value string, set string) bool {
	for i := 0; i < len(value); i++ {
		if isCharInSet(value[i], set) {
			return true
		}
	}
	return false
}

func allCharsInSet(value string, set string) bool {
	for i := 0; i < len(value); i++ {
		if !isCharInSet(value[i], set) {
			return false
		}
	}
	return true
}

func isCharInSet(ch byte, set string) bool {
	for i := 0; i < len(set); i++ {
		if ch == set[i] {
			return true
		}
	}
	return false
}
