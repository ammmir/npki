package npki

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/scrypt"
)

type KeypairType byte

const (
	KeypairTypeInvalid KeypairType = 0x0
	KeypairTypeEd25519             = 0x1
	KeypairTypeDH25519             = 0x2
)

func GenerateDH25519() (Keypair, error) {
	var pubkey, privkey [32]byte

	if _, err := rand.Read(privkey[:]); err != nil {
		return Keypair{}, err
	}

	curve25519.ScalarBaseMult(&pubkey, &privkey)

	return Keypair{
		algo:    KeypairTypeDH25519,
		pubkey:  pubkey[:],
		privkey: privkey[:],
	}, nil
}

func GenerateEd25519() (Keypair, error) {
	if pub, priv, err := ed25519.GenerateKey(nil); err != nil {
		return Keypair{}, err
	} else {
		return Keypair{
			algo:    KeypairTypeEd25519,
			pubkey:  []byte(pub),
			privkey: []byte(priv),
		}, nil
	}
}

var (
	ErrInvalidKeyFormat = errors.New("invalid key format")
	ErrInvalidChecksum  = errors.New("invalid checksum")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrMissingKey       = errors.New("missing key")
)

func DecodeKeypair(data []byte, key []byte, isKDF bool) (Keypair, error) {
	var err error
	var kp Keypair
	var size int

	kp.algo = KeypairType(data[0])

	switch kp.algo {
	case KeypairTypeEd25519:
		size = ed25519.PrivateKeySize
	case KeypairTypeDH25519:
		size = 32
	default:
		return Keypair{}, ErrInvalidKeyFormat
	}

	flagE := data[1]&0x80 == 0x80
	flagS := data[1]&0x40 == 0x40
	flagN := data[1]&0x20 == 0x20

	if flagE {
		size += 16 + chacha20poly1305.NonceSize
	}

	if flagS {
		size += 32 // scrypt salt
	}

	kp.privkey = make([]byte, size)
	kp.pubkey = make([]byte, 32)

	// verify checksum
	digest := sha256.Sum256(data[:2+size])
	if !bytes.Equal(data[2+size:2+size+4], digest[:4]) {
		return Keypair{}, ErrInvalidChecksum
	}

	if flagE { // E
		if key == nil {
			return Keypair{}, ErrMissingKey
		}

		var nonce []byte
		var ciphertext []byte

		if flagS { // S
			if !isKDF {
				return Keypair{}, ErrMissingKey
			}

			salt := data[2 : 2+32]

			if key, err = scrypt.Key(key, salt, 16384, 8, 1, 32); err != nil {
				return Keypair{}, err
			}

			nonce = data[2+32 : 2+32+chacha20poly1305.NonceSize]
			ciphertext = data[2+32+chacha20poly1305.NonceSize : 2+size]
		} else {
			nonce = data[2 : 2+chacha20poly1305.NonceSize]
			ciphertext = data[2+chacha20poly1305.NonceSize : 2+size]
		}

		chacha, err := chacha20poly1305.New(key)
		if err != nil {
			return Keypair{}, err
		}

		key, err = chacha.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return Keypair{}, ErrDecryptionFailed
		}

		copy(kp.privkey, key)
	} else if flagN {
		copy(kp.pubkey, data[2:size+2])
	} else {
		copy(kp.privkey, data[2:size+2])
	}

	if !flagN {
		if kp.algo == KeypairTypeEd25519 {
			copy(kp.pubkey, Ed25519PublicKey(kp.privkey))
		} else if kp.algo == KeypairTypeDH25519 {
			copy(kp.pubkey, DH25519PublicKey(kp.privkey))
		}
	}

	return kp, nil
}

type Keypair struct {
	algo    KeypairType
	pubkey  []byte
	privkey []byte
}

func (t *Keypair) Type() KeypairType {
	return t.algo
}

func (t *Keypair) PublicKey() []byte {
	return t.pubkey
}

func (t *Keypair) PrivateKey() []byte {
	return t.privkey
}

func (t *Keypair) Neuter() {
	t.privkey = make([]byte, 0)
}

func (t *Keypair) Sign(data []byte) ([]byte, error) {
	if t.algo != KeypairTypeEd25519 {
		return nil, ErrInvalidKeyFormat
	}

	return ed25519.Sign(ed25519.PrivateKey(t.privkey), data), nil
}

func (t *Keypair) SignCertificate(cert Certificate) (Certificate, error) {
	cert.Extensions = append(cert.Extensions, Extension{SignedWithEd25519ExtensionType, ExtensionFlagAffectsValidation, t.PublicKey()})

	var err error
	cert.Signature, err = t.Sign(cert.Encode())
	if err != nil {
		return Certificate{}, err
	}

	return cert, nil
}

func (t *Keypair) Encode(key []byte, kdf bool) ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteByte(byte(t.algo)) // Type

	var b byte
	var salt []byte

	if len(key) > 0 {
		// 0th bit: is encrypted
		b |= 0x80 // E

		// 2nd bit: key is a passphrase that should be run through a KDF
		if kdf {
			b |= 0x40 // S

			var err error
			salt = make([]byte, 32)
			if _, err = rand.Read(salt); err != nil {
				return nil, err
			}

			if key, err = scrypt.Key(key, salt, 16384, 8, 1, 32); err != nil {
				return nil, err
			}
		}
	}

	// 3rd bit: neutered
	if len(t.privkey) == 0 {
		b |= 0x20 // N
	}

	buf.WriteByte(b)

	if len(key) > 0 {
		chacha, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}

		nonce := make([]byte, chacha20poly1305.NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}

		ciphertext := chacha.Seal(nil, nonce, t.privkey, nil)

		if len(salt) > 0 {
			buf.Write(salt)
		}

		buf.Write(nonce)
		buf.Write(ciphertext)
	} else if len(t.privkey) > 0 {
		buf.Write(t.privkey)
	} else {
		buf.Write(t.pubkey)
	}

	digest := sha256.Sum256(buf.Bytes())
	buf.Write(digest[:4]) // Checksum

	return buf.Bytes(), nil
}
