package ztls

import (
	"encoding/json"

	"github.com/zmap/ztools/x509"
)

type encodedCertificates struct {
	Certificates       [][]byte            `json:"raw"`
	ParsedCertificate  *x509.Certificate   `json:"certificate"`
	ParsedCertificates []*x509.Certificate `json:"chain"`
}

func (ec *encodedCertificates) FromZTLS(c *Certificates) *encodedCertificates {
	ec.Certificates = c.Certificates
	ec.ParsedCertificate = c.ParsedCertificates[0]
	if len(c.ParsedCertificates) > 1 {
		ec.ParsedCertificates = c.ParsedCertificates[1:]
	}
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
