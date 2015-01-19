package x509

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/zmap/ztools/x509/pkix"
)

func (s *SignatureAlgorithm) MarshalJSON() ([]byte, error) {
	algorithm := *s
	if algorithm >= total_signature_algorithms || algorithm < 0 {
		algorithm = UnknownSignatureAlgorithm
	}
	name := signatureAlgorithmNames[algorithm]
	out := fmt.Sprintf(`{"id":%d,"name":"%s"}`, *s, name)
	return []byte(out), nil
}

func (p *PublicKeyAlgorithm) MarshalJSON() ([]byte, error) {
	algorithm := *p
	if algorithm >= total_key_algorithms || algorithm < 0 {
		algorithm = 0
	}
	name := keyAlgorithmNames[algorithm]
	out := fmt.Sprintf(`{"id":%d,"name":"%s"}`, *p, name)
	return []byte(out), nil
}

type jsonValidity struct {
	NotBefore time.Time `json:"start"`
	NotAfter  time.Time `json:"end"`
}

type jsonSubjectKeyInfo struct {
	KeyAlgorithm PublicKeyAlgorithm     `json:"key_algorithm"`
	PublicKey    map[string]interface{} `json:"public_key"`
}

func (jv *jsonValidity) MarshalJSON() ([]byte, error) {
	start := jv.NotBefore.Format(time.RFC3339)
	end := jv.NotAfter.Format(time.RFC3339)
	s := fmt.Sprintf(`{"start":"%s","end":"%s"}`, start, end)
	return []byte(s), nil
}

type jsonTBSCertificate struct {
	Version            int                    `json:"version"`
	SerialNumber       *big.Int               `json:"serial_number"`
	SignatureAlgorithm SignatureAlgorithm     `json:"signature_algorithm"`
	Issuer             pkix.Name              `json:"issuer"`
	Validity           jsonValidity           `json:"validity"`
	Subject            pkix.Name              `json:"subject"`
	SubjectKeyInfo     jsonSubjectKeyInfo     `json:"subject_key_info"`
	Extensions         *CertificateExtensions `json:"extensions"`
}

type jsonSignature struct {
	Value           []byte `json:"value"`
	Valid           bool   `json:"valid"`
	ValidationError string `json:"validation_error,omitempty"`
	Matches         *bool  `json:"matches_domain"`
	SelfSigned      bool   `json:"self_signed"`
}

type jsonCertificate struct {
	Certificate        jsonTBSCertificate `json:"certificate"`
	SignatureAlgorithm SignatureAlgorithm `json:"signature_algorithm"`
	Signature          jsonSignature      `json:"signature"`
}

func (c *Certificate) MarshalJSON() ([]byte, error) {
	jc := new(jsonCertificate)
	jc.Certificate.Version = c.Version
	jc.Certificate.SerialNumber = c.SerialNumber
	jc.Certificate.SignatureAlgorithm = c.SignatureAlgorithm
	jc.Certificate.Issuer = c.Issuer
	jc.Certificate.Validity.NotBefore = c.NotBefore
	jc.Certificate.Validity.NotAfter = c.NotAfter
	jc.Certificate.Subject = c.Subject
	jc.Certificate.SubjectKeyInfo.KeyAlgorithm = c.PublicKeyAlgorithm

	// Pull out the key
	keyMap := make(map[string]interface{})
	switch c.PublicKeyAlgorithm {
	case RSA:
		rsaKey, ok := c.PublicKey.(*rsa.PublicKey)
		if ok {
			keyMap["modulus"] = rsaKey.N.Bytes()
			keyMap["exponent"] = rsaKey.E
		}
	case DSA:
		dsaKey, ok := c.PublicKey.(*dsa.PublicKey)
		if ok {
			keyMap["p"] = dsaKey.P
			keyMap["q"] = dsaKey.Q
			keyMap["g"] = dsaKey.G
			keyMap["y"] = dsaKey.Y
		}
	case ECDSA:
		ecdsaKey, ok := c.PublicKey.(*ecdsa.PublicKey)
		if ok {
			params := ecdsaKey.Params()
			keyMap["P"] = params.P
			keyMap["N"] = params.N
			keyMap["B"] = params.B
			keyMap["Gx"] = params.Gx
			keyMap["Gy"] = params.Gy
			keyMap["X"] = ecdsaKey.X
			keyMap["Y"] = ecdsaKey.Y
		}
	}
	jc.Certificate.SubjectKeyInfo.PublicKey = keyMap
	jc.Certificate.Extensions = c.jsonifyExtensions()

	// TODO: Handle the fact this might not match
	jc.SignatureAlgorithm = c.SignatureAlgorithm
	jc.Signature.Value = c.Signature
	jc.Signature.Valid = c.valid
	if c.validationError != nil {
		jc.Signature.ValidationError = c.validationError.Error()
	}
	if c.Subject.CommonName == c.Issuer.CommonName {
		jc.Signature.SelfSigned = true
	}
	return json.Marshal(jc)
}
