package npki

import (
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

func Ed25519PublicKey(privkey []byte) []byte {
	if b, ok := ed25519.PrivateKey(privkey).Public().(ed25519.PublicKey); ok {
		return b
	} else {
		return []byte{}
	}
}

func DH25519PublicKey(privkey []byte) []byte {
	var pk [32]byte
	copy(pk[:], privkey)
	var pubkey [32]byte
	curve25519.ScalarBaseMult(&pubkey, &pk)
	return pubkey[:]
}
