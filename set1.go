package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
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
		return nil, fmt.Errorf("len of a and b is not equal")
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
