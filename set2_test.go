package cryptopals

import "testing"

func Test_PadPKCS7(t *testing.T) {
	in := []byte("YELLOW SUBMARINE")
	size := 20
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	actual, err := PadPKCS7(in, size)
	if err != nil {
		t.Fatal(err)
	}
	compareBytes(expected, actual, t)
}
