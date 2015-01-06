package x509

import (
	"encoding/asn1"
	"net"

	"github.com/zmap/ztools/x509/pkix"
)

var (
	oidExtKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtBasicConstraints    = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtSubjectAltName      = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtNameConstraints     = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidCRLDistributionPoints  = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtAuthKeyId           = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtExtendedKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtCertificatePolicy   = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtAuthorityInfoAccess = oidExtensionAuthorityInfoAccess
)

type CertificateExtensions struct {
	KeyUsage              KeyUsage              `json:"key_usage,omitempty"`
	BasicConstraints      BasicConstraints      `json:"basic_constraints,omitempty"`
	SubjectAltName        SubjectAltName        `json:"subject_alt_name,omitempty"`
	NameConstriants       *NameConstriants      `json:"name_constraints,omitempty"`
	CRLDistributionPoints CRLDistributionPoints `json:"crl_distribution_points,omitempty"`
	AuthKeyId             AuthKeyId             `json:"authority_key_id,omitempty"`
	ExtendedKeyUsage      ExtendedKeyUsage      `json:"extended_key_usage,omitempty"`
	CertificatePolicies   CertificatePolicies   `json:"certificate_policies,omitempty"`
	AuthorityInfoAccess   *AuthorityInfoAccess  `json:"authority_info_access,omitempty"`
	UnknownExtensions     []pkix.Extension      `json:"unknown_extensions,omitempty"`
}

type BasicConstraints struct {
	IsCA       bool `json:"is_ca"`
	MaxPathLen *int `json:"max_path_len,omitempty"`
}

type SubjectAltName struct {
	DNSNames       []string `json:"dns_names"`
	EmailAddresses []string `json:"email_addresses"`
	IPAddresses    []net.IP `json:"ip_addresses"`
}

// TODO: Handle excluded names

type NameConstriants struct {
	Critical       bool     `json:"critical"`
	PermittedNames []string `json:"permitted_names"`
}

type CRLDistributionPoints []string

type AuthKeyId []byte

type ExtendedKeyUsage []ExtKeyUsage

type CertificatePolicies []asn1.ObjectIdentifier

// TODO pull out other types
type AuthorityInfoAccess struct {
	OCSPServer            []string `json:"ocsp_urls,omitempty"`
	IssuingCertificateURL []string `json:"issuer_urls,omitempty"`
}

func (c *Certificate) jsonifyExtensions() *CertificateExtensions {
	exts := new(CertificateExtensions)
	for _, e := range c.Extensions {
		if e.Id.Equal(oidExtKeyUsage) {
			exts.KeyUsage = c.KeyUsage
		} else if e.Id.Equal(oidExtBasicConstraints) {
			exts.BasicConstraints.IsCA = c.IsCA
			if c.MaxPathLen > 0 || c.MaxPathLenZero {
				exts.BasicConstraints.MaxPathLen = new(int)
				*exts.BasicConstraints.MaxPathLen = c.MaxPathLen
			}
		} else if e.Id.Equal(oidExtSubjectAltName) {
			exts.SubjectAltName.DNSNames = c.DNSNames
			exts.SubjectAltName.EmailAddresses = c.EmailAddresses
			exts.SubjectAltName.IPAddresses = c.IPAddresses
		} else if e.Id.Equal(oidExtNameConstraints) {
			exts.NameConstriants = new(NameConstriants)
			exts.NameConstriants.Critical = c.PermittedDNSDomainsCritical
			exts.NameConstriants.PermittedNames = c.PermittedDNSDomains
		} else if e.Id.Equal(oidCRLDistributionPoints) {
			exts.CRLDistributionPoints = c.CRLDistributionPoints
		} else if e.Id.Equal(oidExtAuthKeyId) {
			exts.AuthKeyId = c.AuthorityKeyId
		} else if e.Id.Equal(oidExtExtendedKeyUsage) {
			exts.ExtendedKeyUsage = c.ExtKeyUsage
		} else if e.Id.Equal(oidExtCertificatePolicy) {
			exts.CertificatePolicies = c.PolicyIdentifiers
		} else if e.Id.Equal(oidExtAuthorityInfoAccess) {
			exts.AuthorityInfoAccess = new(AuthorityInfoAccess)
			exts.AuthorityInfoAccess.OCSPServer = c.OCSPServer
			exts.AuthorityInfoAccess.IssuingCertificateURL = c.IssuingCertificateURL
		} else {
			// Unknown extension
			exts.UnknownExtensions = append(exts.UnknownExtensions, e)
		}
	}
	return exts
}
