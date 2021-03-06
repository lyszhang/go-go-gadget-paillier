package paillier

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
)

// This example demonstrates basic usage of this library.
// Features shown:
//   * Encrypt/Decrypt
//   * Homomorphic cipher text addition
//   * Homomorphic addition with constant
//   * Homomorphic multiplication with constant
func TestAdd(t *testing.T) {
	// Generate a 128-bit private key.
	privKey, err := GenerateKey(rand.Reader, 1024)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Encrypt the number "15".
	m15 := new(big.Int).SetInt64(-15)
	c15, err := Encrypt(&privKey.PublicKey, m15.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}

	// Decrypt the number "15".
	d, err := Decrypt(privKey, c15)
	if err != nil {
		fmt.Println(err)
		return
	}
	plainText := new(big.Int).SetBytes(d)
	fmt.Println("Decryption Result of 15: ", plainText.String())

	// Now for the fun stuff.
	// Encrypt the number "20".
	m20 := new(big.Int).SetInt64(20)
	c20, err := Encrypt(&privKey.PublicKey, m20.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}

	// Subtract the encrypted integers 20 and 15 together.
	subM20M15 := SubCipher(&privKey.PublicKey, c20, c15)
	decryptedAddition, err := Decrypt(privKey, subM20M15)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Result of 20-15 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 5

	// Add the encrypted integers 15 and 20 together.
	plusM16M20 := AddCipher(&privKey.PublicKey, c15, c20)
	decryptedAddition, err = Decrypt(privKey, plusM16M20)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Result of 15+20 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 35

	// Add the encrypted integer 15 to plaintext constant 10.
	plusE15and10 := Add(&privKey.PublicKey, c15, new(big.Int).SetInt64(10).Bytes())
	decryptedAddition, err = Decrypt(privKey, plusE15and10)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Result of 15+10 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 25

	// Multiply the encrypted integer 15 by the plaintext constant 10.
	mulE15and10 := Mul(&privKey.PublicKey, c15, new(big.Int).SetInt64(10).Bytes())
	decryptedMul, err := Decrypt(privKey, mulE15and10)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Result of 15*10 after decryption: ",
		new(big.Int).SetBytes(decryptedMul).String()) // 150
}



// This example demonstrates basic usage of this library.
// Features shown:
//   * Encrypt/Decrypt
//   * Homomorphic cipher text addition
//   * Homomorphic addition with constant
//   * Homomorphic multiplication with constant
func TestAddHE(t *testing.T) {
	// Generate a 128-bit private key.
	privKey, err := GenerateKey(rand.Reader, 128)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Encrypt the number "15".
	m15 := new(big.Int).SetInt64(15)
	c15, err := Encrypt(&privKey.PublicKey, m15.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}

	pubBytes, _ := json.Marshal(privKey.PublicKey)
	var pub PublicKey
	json.Unmarshal(pubBytes, &pub)

	// Add the encrypted integers 15 and 15 together.
	plusM15M15 := AddCipher(&pub, c15, c15)
	decryptedAddition, err := Decrypt(privKey, plusM15M15)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Result of 15+15 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 35


	// Sub the encrypted integer 15 to plaintext constant 10.
	subE15and10 := SubCipherWithConstant(&privKey.PublicKey, c15, new(big.Int).SetInt64(10).Bytes())
	decryptedAddition, err = Decrypt(privKey, subE15and10)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Result of 15-10 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 5

	// Sub the plaintext constant 20 to encrypted integer 15.
	sub20andE15 := SubConstWithCipher(&privKey.PublicKey, new(big.Int).SetInt64(14).Bytes(), c15)
	decryptedAddition, err = Decrypt(privKey, sub20andE15)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Result of 20-15 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 5
}
