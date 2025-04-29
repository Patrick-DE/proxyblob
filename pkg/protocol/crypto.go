package protocol

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// GenerateKeyPair creates a new X25519 key pair for key exchange.
// Returns a properly clamped private key and its corresponding public key.
func GenerateKeyPair() (privateKey, publicKey []byte) {
	privateKey = make([]byte, curve25519.ScalarSize)
	io.ReadFull(rand.Reader, privateKey)

	// Clamp private key according to X25519 spec
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, _ = curve25519.X25519(privateKey, curve25519.Basepoint)
	return privateKey, publicKey
}

// GenerateNonce creates a random nonce for ChaCha20-Poly1305.
// Returns a cryptographically secure random nonce.
func GenerateNonce() []byte {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	io.ReadFull(rand.Reader, nonce)
	return nonce
}

// DeriveKey performs X25519 key exchange and HKDF key derivation.
// Returns a symmetric key and status code. Key is nil on error.
func DeriveKey(privateKey, peerPublicKey, nonce []byte) ([]byte, byte) {
	// Derive shared secret using X25519
	sharedSecret, err := curve25519.X25519(privateKey, peerPublicKey)
	if err != nil {
		return nil, ErrInvalidCrypto
	}

	// Derive symmetric key using HKDF-SHA3
	kdf := hkdf.New(sha3.New256, sharedSecret, nonce, nil)
	symmetricKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(kdf, symmetricKey); err != nil {
		return nil, ErrInvalidCrypto
	}

	return symmetricKey, ErrNone
}

// Encrypt performs authenticated encryption using ChaCha20-Poly1305.
// Returns (nonce || ciphertext || tag) or nil on error.
func Encrypt(key, plaintext []byte) ([]byte, byte) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrInvalidCrypto
	}

	nonce := GenerateNonce()
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, ErrNone
}

// Decrypt performs authenticated decryption using ChaCha20-Poly1305.
// Returns decrypted plaintext or nil if authentication fails.
func Decrypt(key, ciphertext []byte) ([]byte, byte) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrInvalidCrypto
	}

	if len(ciphertext) < chacha20poly1305.NonceSizeX {
		return nil, ErrInvalidCrypto
	}

	nonce := ciphertext[:chacha20poly1305.NonceSizeX]
	ciphertextBody := ciphertext[chacha20poly1305.NonceSizeX:]

	plaintext, err := aead.Open(nil, nonce, ciphertextBody, nil)
	if err != nil {
		return nil, ErrInvalidCrypto
	}

	return plaintext, ErrNone
}

// Xor performs byte-wise XOR of data with a repeating key.
// Warning: This is NOT cryptographically secure, use only for basic obfuscation.
func Xor(data []byte, key []byte) []byte {
	for i := range data {
		data[i] ^= key[i%len(key)]
	}
	return data
}
