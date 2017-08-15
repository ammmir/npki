package npki

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestCertificate(t *testing.T) {
	rootKeypair, err := GenerateEd25519()
	if err != nil {
		t.Error(err)
	}

	childKeypair, err := GenerateDH25519()
	if err != nil {
		t.Error(err)
	}

	expiresTime := time.Now().Add(2 * time.Second)

	cert := NewCertificate(childKeypair.PublicKey(), expiresTime)
	signedCert, err := rootKeypair.SignCertificate(cert)
	if err != nil {
		t.Error(err)
	}

	buf := signedCert.Encode()

	if buf[0] != 0x01 {
		t.Errorf("version: %v", buf[0])
	}

	if buf[1] != byte(CertAuthKeyType) {
		t.Errorf("cert type: %v", buf[1])
	}

	fromTime := time.Unix(int64(binary.LittleEndian.Uint64(buf[2:])), 0)

	if fromTime.Unix() < 0 {
		t.Errorf("cert validity time: %v", fromTime)
	}

	toTime := time.Unix(int64(binary.LittleEndian.Uint64(buf[10:])), 0)

	if toTime.Unix() != expiresTime.Unix() {
		t.Errorf("cert expiration time: %v", toTime)
	}

	if buf[18] != 0x02 {
		t.Errorf("cert key type type: %v", buf[18])
	}

	certifiedKey := buf[19 : 19+32]
	if !bytes.Equal(certifiedKey, childKeypair.PublicKey()) {
		t.Error("certified public key does not match")
	}

	extCount := int(buf[51])
	if extCount != 1 {
		t.Errorf("extension count: %v", extCount)
	}

	extLen := binary.LittleEndian.Uint16(buf[52:])

	if extLen != 32 {
		t.Errorf("extension length: %v", extLen)
	}

	if buf[54] != byte(SignedWithEd25519ExtensionType) {
		t.Errorf("extension type: %v", buf[54])
	}

	if buf[55] != byte(ExtensionFlagAffectsValidation) {
		t.Errorf("extension flags: %v", buf[55])
	}

	if !bytes.Equal(buf[56:56+32], rootKeypair.PublicKey()) {
		t.Error("SignedWithEd25519ExtensionType public key mismatch")
	}
}
