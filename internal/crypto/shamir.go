package crypto

import (
	"crypto/rand"
	"fmt"
)

const (
	// gfReduce is the low byte of the AES irreducible polynomial (0x11b).
	gfReduce     = 0x1b
	gfOrder      = 256
	maxShares    = gfOrder - 1
	minThreshold = 2 // nilai t
)

type Share struct {
	X byte
	Y []byte
}

// validasi threshold
func SplitSecret(secret []byte, threshold int, total int) ([]Share, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret must not be empty")
	}
	if threshold < minThreshold {
		return nil, fmt.Errorf("threshold must be >= %d", minThreshold)
	}
	if total < threshold {
		return nil, fmt.Errorf("total shares must be >= threshold")
	}
	if threshold > maxShares {
		return nil, fmt.Errorf("threshold must be <= %d", maxShares)
	}
	if total > maxShares {
		return nil, fmt.Errorf("total shares must be <= %d", maxShares)
	}

	coeffs := make([][]byte, threshold)   // f(x) = S + a1*x + a2*x^2 + ... + a(t-1)*x^(t-1)
	coeffs[0] = make([]byte, len(secret)) // coeffs[0] = S (secret)
	copy(coeffs[0], secret)
	for i := 1; i < threshold; i++ {
		coeffs[i] = make([]byte, len(secret))
		if _, err := rand.Read(coeffs[i]); err != nil { // random koefisien pake crypto/rand
			return nil, fmt.Errorf("read random coefficients: %w", err)
		}
	}

	shares := make([]Share, total)
	for i := 0; i < total; i++ {
		x := byte(i + 1)
		y := make([]byte, len(secret))
		for idx := range secret {
			y[idx] = evalPolynomial(coeffs, x, idx)
		}
		shares[i] = Share{X: x, Y: y}
	}

	return shares, nil
}

// menggabungkan share
func CombineShares(shares []Share) ([]byte, error) {
	if len(shares) < minThreshold {
		return nil, fmt.Errorf("need at least %d shares", minThreshold)
	}
	shareLen := len(shares[0].Y)
	if shareLen == 0 {
		return nil, fmt.Errorf("share data must not be empty")
	}

	seen := make(map[byte]struct{}, len(shares))
	for i, share := range shares {
		if share.X == 0 {
			return nil, fmt.Errorf("share %d has invalid X=0", i)
		}
		if len(share.Y) != shareLen {
			return nil, fmt.Errorf("share %d length mismatch", i)
		}
		if _, exists := seen[share.X]; exists {
			return nil, fmt.Errorf("duplicate share X=%d", share.X)
		}
		seen[share.X] = struct{}{}
	}

	secret := make([]byte, shareLen)
	for idx := 0; idx < shareLen; idx++ {
		b, err := lagrangeInterpolation(shares, idx)
		if err != nil {
			return nil, fmt.Errorf("reconstruct byte %d: %w", idx, err)
		}
		secret[idx] = b
	}

	return secret, nil
}

// menghitung f(x) --> menghasilkan share baru
func evalPolynomial(coeffs [][]byte, x byte, index int) byte {
	y := coeffs[len(coeffs)-1][index]
	for i := len(coeffs) - 2; i >= 0; i-- {
		y = gfAdd(gfMul(y, x), coeffs[i][index])
	}
	return y
}

// menghitung f(x) pada x = 0 --> mengambil kembali secret dari share
func lagrangeInterpolation(shares []Share, index int) (byte, error) {
	var result byte
	for i, si := range shares {
		numerator := byte(1)
		denominator := byte(1)
		for j, sj := range shares {
			if i == j {
				continue
			}
			numerator = gfMul(numerator, sj.X)
			diff := gfAdd(sj.X, si.X)
			if diff == 0 {
				return 0, fmt.Errorf("duplicate share X=%d", si.X)
			}
			denominator = gfMul(denominator, diff)
		}
		coeff, err := gfDiv(numerator, denominator)
		if err != nil {
			return 0, err
		}
		term := gfMul(si.Y[index], coeff)
		result = gfAdd(result, term)
	}

	return result, nil
}

// penjumlahan di GF(256)
func gfAdd(a, b byte) byte {
	return a ^ b
}

// perkalian di GF(256)
func gfMul(a, b byte) byte {
	var p byte
	aa := a
	bb := b
	for bb != 0 {
		if bb&1 != 0 {
			p ^= aa
		}
		carry := aa & 0x80
		aa <<= 1
		if carry != 0 {
			aa ^= gfReduce
		}
		bb >>= 1
	}
	return p
}

// perpangkatan di GF(256)
func gfPow(a byte, exp int) byte {
	if exp == 0 {
		return 1
	}
	result := byte(1)
	base := a
	e := exp
	for e > 0 {
		if e&1 == 1 {
			result = gfMul(result, base)
		}
		base = gfMul(base, base)
		e >>= 1
	}
	return result
}

// pembagian di GF(256)
func gfDiv(a, b byte) (byte, error) {
	if b == 0 {
		return 0, fmt.Errorf("division by zero")
	}
	inv := gfPow(b, gfOrder-2)
	return gfMul(a, inv), nil
}
