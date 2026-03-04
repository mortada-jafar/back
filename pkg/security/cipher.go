package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

// Cipher wraps an AEAD cipher for packet encryption/decryption.
type Cipher struct {
	aead      cipher.AEAD
	algorithm string
}

// NewCipher creates an encryption cipher from config parameters.
func NewCipher(algorithm, pskBase64 string, kdfIterations int) (*Cipher, error) {
	pskRaw, err := base64.StdEncoding.DecodeString(pskBase64)
	if err != nil {
		return nil, fmt.Errorf("decode PSK: %w", err)
	}

	salt := sha256sum([]byte("backhaul-core-kdf-salt"))

	var keyLen int
	switch algorithm {
	case "aes-128-gcm":
		keyLen = 16
	case "aes-256-gcm":
		keyLen = 32
	case "chacha20-poly1305":
		keyLen = 32
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	key := pbkdf2.Key(pskRaw, salt, kdfIterations, keyLen, sha256.New)

	var aead cipher.AEAD
	switch algorithm {
	case "aes-128-gcm", "aes-256-gcm":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	case "chacha20-poly1305":
		aead, err = chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
	}

	return &Cipher{aead: aead, algorithm: algorithm}, nil
}

// Encrypt: output = nonce || ciphertext || tag
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt.
func (c *Cipher) Decrypt(data []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return c.aead.Open(nil, data[:ns], data[ns:], nil)
}

// Overhead returns total bytes added (nonce + tag).
func (c *Cipher) Overhead() int {
	return c.aead.NonceSize() + c.aead.Overhead()
}

// --- Token-based auth (non-IPX transports) ---

// TokenAuth handles HMAC-SHA256 token verification for non-IPX transports.
type TokenAuth struct {
	token []byte
}

func NewTokenAuth(token string) *TokenAuth {
	return &TokenAuth{token: []byte(token)}
}

// Sign produces an HMAC-SHA256 signature for the given data.
func (t *TokenAuth) Sign(data []byte) []byte {
	mac := hmac.New(sha256.New, t.token)
	mac.Write(data)
	return mac.Sum(nil)
}

// Verify checks an HMAC-SHA256 signature.
func (t *TokenAuth) Verify(data, sig []byte) bool {
	expected := t.Sign(data)
	return hmac.Equal(expected, sig)
}

// GeneratePSK creates a random 32-byte base64-encoded PSK.
func GeneratePSK() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func sha256sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
