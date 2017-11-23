package cryptopals

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"strings"
	"testing"
)

func Test_Challenge1(t *testing.T) {
	const expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	actual, err := HexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		t.Fatal(err)
	}

	if expected != actual {
		t.Errorf("expected:\t%s\nactual:\t%s", expected, actual)
	}
}

func decodeHex(str string, t *testing.T) []byte {
	decoded, err := hex.DecodeString(str)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func compareBytes(a, b []byte, t *testing.T) {
	if !bytes.Equal(a, b) {
		t.Errorf("a: %s\nb: %s", a, b)
	}
}

func Test_Challenge2(t *testing.T) {
	expected := decodeHex("746865206b696420646f6e277420706c6179", t)

	a := decodeHex("1c0111001f010100061a024b53535009181c", t)
	b := decodeHex("686974207468652062756c6c277320657965", t)

	actual, err := XORvsXOR(a, b)
	if err != nil {
		t.Fatal(err)
	}

	compareBytes(expected, actual, t)
}

func charFreqFromFile(path string) CharFrequency {
	text, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return CalculateCharacterFrequency(string(text))
}

var cf = charFreqFromFile("testdata/mobydick.txt")

func Test_Challenge3(t *testing.T) {
	in := decodeHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", t)
	key, val, score := BreakSingleByteXOR(in, cf)
	t.Logf("key: %s, val: %s, score: %v", string(key), string(val), score)
}

func Test_Challenge4(t *testing.T) {
	var (
		key   byte
		val   []byte
		score float64
	)
	data, err := ioutil.ReadFile("testdata/set1c4.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, str := range strings.Split(string(data), "\n") {
		in := decodeHex(str, t)
		k, v, s := BreakSingleByteXOR(in, cf)
		if s > score {
			key = k
			val = v
			score = s
		}
	}
	t.Logf("key: %s, val: %s, score: %v", string(key), string(val), score)
}

func Test_Challenge5(t *testing.T) {
	expected := decodeHex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", t)
	actual := RepeatingXOR([]byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`), []byte("ICE"))

	compareBytes(expected, actual, t)
}

func decodeBase64(str string, t *testing.T) []byte {
	decoded, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func Test_Challenge6(t *testing.T) {
	hd, err := hammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	if err != nil {
		t.Fatal(err)
	}
	if hd != 37 {
		t.Fatalf("wrong hamming distance: %d", hd)
	}

	file, err := ioutil.ReadFile("testdata/set1c6.txt")
	if err != nil {
		t.Fatal(err)
	}
	in := decodeBase64(string(file), t)

	keySize, err := GuessRepeatingXORKeySize(in, 2, 40)
	if err != nil {
		t.Fatal(err)
	}
	key, err := BreakRepeatingXORKey(in, keySize, cf)
	if err != nil {
		t.Fatal(err)
	}
	decrypted := RepeatingXOR(in, key)

	t.Logf("key: %s\ndecrypted: %s", key, decrypted)
}

func Test_Challenge7(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/set1c7.txt")
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptAESECB(decodeBase64(string(data), t), []byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("decrypted: %s", decrypted)
}

func Test_Challenge8(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/set1c8.txt")
	if err != nil {
		t.Fatal(err)
	}
	for line, str := range strings.Split(string(data), "\n") {
		isECB, err := IsAESECB(decodeHex(str, t))
		if err != nil {
			t.Fatal(err)
		}
		if isECB {
			t.Logf("line %d: %s", line+1, str)
		}
	}
}
