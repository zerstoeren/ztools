package x509

import (
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
	KeyAlgorithm PublicKeyAlgorithm `json:"key_algorithm"`
}

func (jv *jsonValidity) MarshalJSON() ([]byte, error) {
	start := jv.NotBefore.Format(time.RFC3339)
	end := jv.NotAfter.Format(time.RFC3339)
	s := fmt.Sprintf(`{"start":"%s","end":"%s"}`, start, end)
	return []byte(s), nil
}

type jsonSignature struct {
}

type jsonTBSCertificate struct {
	Version            int                `json:"version"`
	SerialNumber       *big.Int           `json:"serial_number"`
	SignatureAlgorithm SignatureAlgorithm `json:"signature_algorithm"`
	Issuer             pkix.Name          `json:"issuer"`
	Validity           jsonValidity       `json:"validity"`
	Subject            pkix.Name          `json:"subject"`
	SubjectKeyInfo     jsonSubjectKeyInfo `json:"subject_key_info"`
}

type jsonCertificate struct {
	Certificate jsonTBSCertificate `json:"certificate"`
	Algorithm   SignatureAlgorithm `json:"signature_algorithm"`
	Signature   jsonSignature      `json:"signature"`
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
	return json.Marshal(jc)
}
