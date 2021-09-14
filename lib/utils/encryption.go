package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encdec/lib/stores"
	"encoding/hex"
	"fmt"
	"io"
	"log"
)

func GenKeyString(v string) {
	sum := sha256.Sum256([]byte(v))
	sha256str := fmt.Sprintf("%x", sum)
	_runes := []rune(sha256str)
	sha256str = string(_runes[0:32])
	bytes := []byte(sha256str)
	stores.Config.KeyString = hex.EncodeToString(bytes)
	fmt.Println(stores.Config.KeyString)
}

// Encrypt function to encrypt string
func Encrypt(stringToEncrypt string) (encryptedString string) {

	//Since the key is in string, we need to convert decode it to bytes
	key, _ := hex.DecodeString(stores.Config.KeyString)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err.Error())
		return "Error"
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err.Error())
		return "Error"
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println(err.Error())
		return "Error"
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}

// Decrypt function to decrypt string
func Decrypt(encryptedString string) (decryptedString string) {

	key, _ := hex.DecodeString(stores.Config.KeyString)
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err.Error())
		return "Error"
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err.Error())
		return "Error"
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()
	if nonceSize > len(enc) {
		return "Error"
	}

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println(err.Error())
		return "Error"
	}

	return fmt.Sprintf("%s", plaintext)
}
