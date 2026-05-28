package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	minPasswordLength = 8
	uppercaseLetters  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowercaseLetters  = "abcdefghijklmnopqrstuvwxyz"
	digits            = "0123456789"
	symbols           = "!@#$%^&*()-_=+[]{}<>?/|"
)

// menghasilkan password random
func GeneratePassword(length int) (string, error) {
	if length < minPasswordLength {
		return "", fmt.Errorf("length must be >= %d", minPasswordLength)
	}

	requiredSets := []string{uppercaseLetters, lowercaseLetters, digits, symbols}
	allChars := uppercaseLetters + lowercaseLetters + digits + symbols

	password := make([]byte, 0, length)
	for _, set := range requiredSets {
		idx, err := randomInt(len(set))
		if err != nil {
			return "", fmt.Errorf("select required char: %w", err)
		}
		password = append(password, set[idx])
	}

	for len(password) < length {
		idx, err := randomInt(len(allChars))
		if err != nil {
			return "", fmt.Errorf("select char: %w", err)
		}
		password = append(password, allChars[idx])
	}

	// shuffle posisi karakter (Fisher-Yates shuffle)
	for i := len(password) - 1; i > 0; i-- {
		j, err := randomInt(i + 1)
		if err != nil {
			return "", fmt.Errorf("shuffle: %w", err)
		}
		password[i], password[j] = password[j], password[i]
	}

	return string(password), nil
}

// menghasilkan angka random
func randomInt(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("max must be positive")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, fmt.Errorf("random int: %w", err)
	}
	return int(n.Int64()), nil
}
