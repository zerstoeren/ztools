package pkix

import (
	"encoding/json"

	"github.com/zmap/ztools/zlog"
	"github.com/zmap/ztools/zson"
)

type jsonName struct {
	CommonName         zson.StringOrArray      `json:"common_name,omitempty"`
	SerialNumber       zson.StringOrArray      `json:"serial_number,omitempty"`
	Country            zson.StringOrArray      `json:"country,omitempty"`
	Locality           zson.StringOrArray      `json:"locality,omitempty"`
	Province           zson.StringOrArray      `json:"province,omitempty"`
	StreetAddress      zson.StringOrArray      `json:"street_address,omitempty"`
	Organization       zson.StringOrArray      `json:"organization,omitempty"`
	OrganizationalUnit zson.StringOrArray      `json:"organizational_unit,omitempty"`
	PostalCode         zson.StringOrArray      `json:"postal_code,omitempty"`
	UnknownAttributes  []AttributeTypeAndValue `json:"unknown_attributes,omitempty"`
}

type jsonAttributeTypeAndValue struct {
	Type  string      `json:"type"`
	Value interface{} `json:"value"`
}

func (a *AttributeTypeAndValue) MarshalJSON() ([]byte, error) {
	var enc jsonAttributeTypeAndValue
	enc.Type = a.Type.String()
	enc.Value = a.Value
	return json.Marshal(&enc)
}

type jsonExtension struct {
	Id       string `json:"id"`
	Critical bool   `json:"critical"`
	Value    []byte `json:"value"`
}

func (e *Extension) MarshalJSON() ([]byte, error) {
	ext := jsonExtension{
		Id:       e.Id.String(),
		Critical: e.Critical,
		Value:    e.Value,
	}
	return json.Marshal(ext)
}

func (n *Name) MarshalJSON() ([]byte, error) {
	var enc jsonName
	attrs := n.ToRDNSequence()
	for _, attrSet := range attrs {
		for _, a := range attrSet {
			zlog.Debug(a)
			s, _ := a.Value.(string)
			if a.Type.Equal(oidCommonName) {
				enc.CommonName = append(enc.CommonName, s)
			} else if a.Type.Equal(oidSerialNumber) {
				enc.SerialNumber = append(enc.SerialNumber, s)
			} else if a.Type.Equal(oidCountry) {
				enc.Country = append(enc.Country, s)
			} else if a.Type.Equal(oidLocality) {
				enc.Locality = append(enc.Locality, s)
			} else if a.Type.Equal(oidProvince) {
				enc.Province = append(enc.Province, s)
			} else if a.Type.Equal(oidStreetAddress) {
				enc.StreetAddress = append(enc.StreetAddress, s)
			} else if a.Type.Equal(oidOrganization) {
				enc.Organization = append(enc.Organization, s)
			} else if a.Type.Equal(oidOrganizationalUnit) {
				enc.OrganizationalUnit = append(enc.OrganizationalUnit, s)
			} else if a.Type.Equal(oidPostalCode) {
				enc.PostalCode = append(enc.PostalCode, s)
			} else {
				enc.UnknownAttributes = append(enc.UnknownAttributes, a)
			}
		}
	}
	return json.Marshal(enc)
}
