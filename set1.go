package cryptopals

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/bits"
	"unicode/utf8"
)

// challenge 1
func HexToBase64(v string) (string, error) {
	decoded, err := hex.DecodeString(v)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(decoded), nil
}

// ----

// challenge 2
func XORvsXOR(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("a and b are not equal length")
	}

	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i]
	}
	return res, nil
}

// ----

func XORvsKey(in []byte, key byte) []byte {
	res := make([]byte, len(in))
	for i := range in {
		res[i] = in[i] ^ key
	}
	return res
}

type CharFrequency map[rune]float64

func CalculateCharacterFrequency(text string) CharFrequency {
	chars := make(CharFrequency)
	for _, char := range text {
		chars[char]++
	}
	total := utf8.RuneCountInString(text)
	for char := range chars {
		chars[char] = chars[char] / float64(total)
	}
	return chars
}

func scoreUTF8String(str string, cf CharFrequency) (score float64) {
	for _, char := range str {
		score += cf[char]
	}
	return score / float64(utf8.RuneCountInString(str))
}

// challenge 3
func BreakSingleByteXOR(in []byte, cf CharFrequency) (key byte, val []byte, score float64) {
	for k := 0; k < 256; k++ {
		v := XORvsKey(in, byte(k))
		s := scoreUTF8String(string(v), cf)
		if s > score {
			key = byte(k)
			val = v
			score = s
		}
	}
	return
}

// ----

// challenge 5
func RepeatingXOR(in, key []byte) []byte {
	res := make([]byte, len(in))
	for i := range in {
		res[i] = in[i] ^ key[i%len(key)]
	}
	return res
}

// ----

func hammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, fmt.Errorf("a and b are not equal length")
	}
	var res int
	for i := range a {
		res += bits.OnesCount8(a[i] ^ b[i])
	}
	return res, nil
}

func GuessRepeatingXORKeySize(in []byte, minKeySize, maxKeySize int) (int, error) {
	var (
		score = math.MaxFloat64
		res   int
	)
	for ks := minKeySize; ks <= maxKeySize; ks++ {
		fst, snd := in[:ks*4], in[ks*4:ks*4*2]
		hd, err := hammingDistance(fst, snd)
		if err != nil {
			return 0, err
		}
		s := float64(hd) / float64(ks)
		if s < score {
			res = ks
			score = s
		}
	}
	return res, nil
}

// challenge 6
func BreakRepeatingXORKey(in []byte, keySize int, cf CharFrequency) ([]byte, error) {
	key := make([]byte, keySize)
	for i := 0; i < keySize; i++ {
		transposed := make([]byte, len(in)/keySize)
		for j := 0; j < len(in)/keySize; j++ {
			transposed[j] = in[i+keySize*j]
		}
		k, _, _ := BreakSingleByteXOR(transposed, cf)
		key[i] = k
	}
	return key, nil
}

// ----

// https://codereview.appspot.com/7860047

// challenge 6
func DecryptAESECB(in, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(in)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("not full blocks")
	}

	res := make([]byte, len(in))
	for i := 0; i < len(in); i += block.BlockSize() {
		block.Decrypt(res[i:], in[i:])
	}

	return res, nil
}

// ----

func IsAESECB(in []byte) (bool, error) {
	const bs = 16
	if len(in)%bs != 0 {
		return false, fmt.Errorf("not full blocks")
	}
	blocks := make(map[string]int)
	for i := 0; i < len(in); i += bs {
		val := string(in[i : i+bs])
		if blocks[val] > 0 {
			return true, nil
		}
		blocks[val]++
	}
	return false, nil
}
