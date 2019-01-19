package npki

import (
	"bytes"
	"testing"
)

func TestEd25519(t *testing.T) {
	kp, err := GenerateEd25519()
	if err != nil {
		t.Error(err)
	}

	buf, err := kp.Encode([]byte("secret"), true)
	if err != nil {
		t.Error(err)
	}

	if buf[0] != 0x01 {
		t.Errorf("byte 0: %v   ", buf[0])
	}

	if buf[1] != 0xC0 {
		t.Errorf("byte 1: %v", buf[1])
	}

	recon, err := DecodeKeypair(buf, []byte("secret"), true)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(recon.PrivateKey(), kp.PrivateKey()) {
		t.Errorf("encoded/decoded private key does not match:\ndecoded: %v\nencoded: %v\n", recon.PrivateKey(), kp.PrivateKey())
	}

	if !bytes.Equal(Ed25519PublicKey(kp.PrivateKey()), kp.PublicKey()) {
		t.Error("derive public key from private key")
	}

	kp.Neuter()
	buf, err = kp.Encode(nil, true)
	if err != nil {
		t.Error(err)
	}

	if buf[0] != 0x01 {
		t.Errorf("byte 0: %v", buf[0])
	}

	if buf[1] != 0x20 {
		t.Errorf("byte 1: %v", buf[1])
	}
}

func TestDH25519(t *testing.T) {
	kp, err := GenerateDH25519()
	if err != nil {
		t.Error(err)
	}

	buf, err := kp.Encode([]byte("secret"), true)
	if err != nil {
		t.Error(err)
	}

	if buf[0] != 0x02 {
		t.Errorf("byte 0: %v   ", buf[0])
	}

	if buf[1] != 0xC0 {
		t.Errorf("byte 1: %v", buf[1])
	}

	if !bytes.Equal(DH25519PublicKey(kp.PrivateKey()), kp.PublicKey()) {
		t.Error("derive public key from private key")
	}

	kp.Neuter()
	buf, err = kp.Encode(nil, true)
	if err != nil {
		t.Error(err)
	}

	if buf[0] != 0x02 {
		t.Errorf("byte 0: %v", buf[0])
	}

	if buf[1] != 0x20 {
		t.Errorf("byte 1: %v", buf[1])
	}
}
