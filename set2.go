package cryptopals

import "fmt"

func PadPKCS7(in []byte, size int) ([]byte, error) {
	// https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
	if size <= 0 || size > 256 {
		return nil, fmt.Errorf("invalid size %d, it should be 1...255", size)
	}

	inLen := len(in)
	padLen := size - inLen%size
	padded := make([]byte, inLen+padLen)
	copy(padded, in)
	for i := 0; i < padLen; i++ {
		padded[inLen+i] = byte(padLen)
	}
	return padded, nil
}
