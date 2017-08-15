package npki

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/ed25519"
)

func DecodeCertificate(data []byte) (Certificate, error) { // TODO
	cert := Certificate{raw: data}

	cert.Version = data[0]
	cert.Type = CertificateType(data[1])

	// from date

	// to date

	// ...

	return cert, nil
}

func VerifyCertificate(cert *Certificate, signingCert *Certificate) (bool, error) {
	return true, nil
}

type CertificateType uint8
type PublicKey []byte
type ExtensionType uint8
type ExtensionFlag uint8

const (
	CertSiginingKeyType CertificateType = 0x01
	CertAuthKeyType     CertificateType = 0x02

	SignedWithEd25519ExtensionType = 0x01
	HostnameExtensionType          = 0x02 // IP address or DNS name

	ExtensionFlagNone              = 0x00
	ExtensionFlagAffectsValidation = 0x01 // CRITICAL
)

var (
	ErrInvalidSigner            = errors.New("invalid signer")
	ErrCertificateNotYetValid   = errors.New("certificate is not yet valid")
	ErrCertificateExpired       = errors.New("certificate has expired")
	ErrMissingCriticalExtension = errors.New("missing critical extension")
	ErrCriticalExtensionInvalid = errors.New("critical extension invalid")
	ErrVerifyFailed             = errors.New("signature verification failed")
)

func NewCertificate(pubkey PublicKey, validTo time.Time) Certificate {
	kind := CertAuthKeyType

	return Certificate{
		Version:            0x1,
		Type:               kind,
		ValidFrom:          time.Now(),
		ValidTo:            validTo,
		KeyType:            KeypairTypeDH25519, //TODO FIXME
		CertifiedPublicKey: pubkey,
		Extensions:         make([]Extension, 0),
	}
}

type Extension struct {
	Type  ExtensionType
	Flags ExtensionFlag
	Data  []byte
}

func (t *Extension) Encode() []byte {
	data := make([]byte, 4+len(t.Data))

	binary.LittleEndian.PutUint16(data[:], uint16(len(t.Data)))
	data[2] = byte(t.Type)
	data[3] = byte(t.Flags)
	copy(data[4:], t.Data)

	return data
}

type Certificate struct {
	raw                []byte
	Version            uint8
	Type               CertificateType
	ValidFrom          time.Time
	ValidTo            time.Time
	KeyType            KeypairType
	CertifiedPublicKey PublicKey
	Extensions         []Extension
	Signature          []byte
}

func (t *Certificate) Verify(rootKey Keypair, critical bool) (bool, error) {
	var signingKey []byte
	for _, ext := range t.Extensions {
		if ext.Type == SignedWithEd25519ExtensionType {
			signingKey = ext.Data
			break
		}
	}

	if signingKey == nil {
		return false, ErrMissingCriticalExtension
	}

	if !bytes.Equal([]byte(rootKey.pubkey), signingKey) {
		return false, ErrInvalidSigner
	}

	if !ed25519.Verify(rootKey.PublicKey(), t.raw[:len(t.raw)-len(t.Signature)], t.Signature) {
		return false, ErrVerifyFailed
	}

	if critical {
		// TOOD: check from date
		// TODO: check to date
		// TODO: check extensions
	}

	return true, nil
}

func (t *Certificate) Encode() []byte {
	var buf bytes.Buffer

	buf.WriteByte(byte(t.Version))
	buf.WriteByte(byte(t.Type))

	// write 64-bit valid from time
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(t.ValidFrom.Unix()))
	buf.Write(b)

	// write 64-bit valid to time
	binary.LittleEndian.PutUint64(b, uint64(t.ValidTo.Unix()))
	buf.Write(b)

	buf.WriteByte(byte(t.KeyType))
	buf.Write(t.CertifiedPublicKey[:])
	buf.WriteByte(uint8(len(t.Extensions)))

	for _, ext := range t.Extensions {
		buf.Write(ext.Encode())
	}

	buf.Write(t.Signature)

	return buf.Bytes()
}
