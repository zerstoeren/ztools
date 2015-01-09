package ztls

import (
	"encoding/json"

	"github.com/zmap/ztools/x509"
)

type encodedCertificates struct {
	Certificates      [][]byte          `json:"certificates"`
	ParsedCertificate *x509.Certificate `json:"parsed_certificate"`
}

func (ec *encodedCertificates) FromZTLS(c *Certificates) *encodedCertificates {
	ec.Certificates = c.Certificates
	ec.ParsedCertificate = c.ParsedCertificate
	return ec
}

func (c *Certificates) FromEncoded(ec *encodedCertificates) *Certificates {
	c.Certificates = ec.Certificates
	// TODO actually parse the parsed cert
	return c
}

func (c *Certificates) MarshalJSON() ([]byte, error) {
	ec := new(encodedCertificates).FromZTLS(c)
	return json.Marshal(ec)
}

func (c *Certificates) UnmarshalJSON(b []byte) error {
	ec := new(encodedCertificates)
	if err := json.Unmarshal(b, ec); err != nil {
		return err
	}
	c.FromEncoded(ec)
	return nil
}
