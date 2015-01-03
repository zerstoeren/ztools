package x509

import (
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/zmap/ztools/x509/pkix"
	"github.com/zmap/ztools/zlog"
)

type jsonTBSCertificate struct {
	Version            int                `json:"version"`
	SerialNumber       *big.Int           `json:"serial_number"`
	SignatureAlgorithm SignatureAlgorithm `json:"signature_algorithm"`
	Issuer             pkix.Name          `json:"issuer"`
	Validity           jsonValidity       `json:"validity"`
	Subject            pkix.Name          `json:"subject"`
}

type jsonValidity struct {
	NotBefore time.Time `json:"start"`
	NotAfter  time.Time `json:"end"`
}

func (jv *jsonValidity) MarshalJSON() ([]byte, error) {
	start := jv.NotBefore.Format(time.RFC3339)
	end := jv.NotAfter.Format(time.RFC3339)
	s := fmt.Sprintf(`{"start":"%s","end":"%s"}`, start, end)
	zlog.Debug(s)
	return []byte(s), nil
}

type jsonSignature struct {
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
	return json.Marshal(jc)
}
