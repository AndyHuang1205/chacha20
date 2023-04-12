package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/chacha20"
	"io"
	"os"
	"strings"
)

func encrypt(key, nonce []byte, plaintext string) []byte {

	plaintextByte := []byte(plaintext)
	block, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
	ciphertext := make([]byte, len(plaintextByte))
	block.XORKeyStream(ciphertext, plaintextByte)

	return ciphertext
}

func decrypt(key, nonce, ciphertext []byte) string {
	block, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
	plaintext := make([]byte, len(ciphertext))
	block.XORKeyStream(plaintext, ciphertext)
	decryptedText := string(plaintext)

	return decryptedText
}
func main() {

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter text to be encrypted: ")
	input, _ := reader.ReadString('\n')
	plaintext := strings.TrimSuffix(input, "\n")
	key := make([]byte, chacha20.KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	nonce := make([]byte, chacha20.NonceSize)

	keyHex := hex.EncodeToString(key)
	nonceHex := hex.EncodeToString(nonce)

	// Encrypt
	ciphertext := encrypt(key, nonce, plaintext)

	// Print results
	fmt.Printf("Encryption: %x\n", ciphertext)
	fmt.Printf("Nonce: %s\n", nonceHex)
	fmt.Printf("Key: %s\n", keyHex)

	// Decryption
	decryptedText := decrypt(key, nonce, ciphertext)
	fmt.Printf("Decryption text: %s\n", decryptedText)
}
