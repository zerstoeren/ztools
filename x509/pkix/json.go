package pkix

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"

	"github.com/zmap/ztools/zlog"
)

type jsonName struct {
	CommonName *string         `json:"common_name"`
	Attributes []jsonAttribute `json:"attributes"`
}

type jsonAttribute struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
}

var unknownNameRegex = regexp.MustCompile(`unknown_attribute_(\d+)`)

func toJSONAttribute(a *AttributeTypeAndValue) (ja jsonAttribute) {
	// Pull out the name
	if reflect.DeepEqual(a.Type, asn1.ObjectIdentifier(oidCountry)) {
		ja.Name = "country"
	} else if reflect.DeepEqual(a.Type, asn1.ObjectIdentifier(oidOrganization)) {
		ja.Name = "organization"
	} else if reflect.DeepEqual(a.Type, asn1.ObjectIdentifier(oidOrganizationalUnit)) {
		ja.Name = "organizational_unit"
	} else if reflect.DeepEqual(a.Type, asn1.ObjectIdentifier(oidCommonName)) {
		ja.Name = "common_name"
	} else if reflect.DeepEqual(a.Type, asn1.ObjectIdentifier(oidSerialNumber)) {
		ja.Name = "serial_number"
	} else if reflect.DeepEqual(a.Type, asn1.ObjectIdentifier(oidLocality)) {
		ja.Name = "locality"
	} else if reflect.DeepEqual(a.Type, asn1.ObjectIdentifier(oidProvince)) {
		ja.Name = "province"
	} else if reflect.DeepEqual(a.Type, asn1.ObjectIdentifier(oidStreetAddress)) {
		ja.Name = "street_address"
	} else if reflect.DeepEqual(a.Type, asn1.ObjectIdentifier(oidPostalCode)) {
		ja.Name = "postal_code"
	} else {
		hexBytes := make([]byte, len(a.Type))
		for idx, val := range a.Type {
			hexBytes[idx] = byte(val)
		}
		ja.Name = "unknown_attribute_" + hex.EncodeToString(hexBytes)
	}
	// Assume the value is a string, if not don't log
	ja.Value, _ = a.Value.(string)
	return
}

func fromJSONAttribute(ja jsonAttribute) (a AttributeTypeAndValue) {
	switch ja.Name {
	case "country":
		a.Type = oidCountry
	case "organization":
		a.Type = oidOrganization
	case "organizational_unit":
		a.Type = oidOrganizationalUnit
	case "common_name":
		a.Type = oidCommonName
	case "serial_number":
		a.Type = oidSerialNumber
	case "locality":
		a.Type = oidLocality
	case "province":
		a.Type = oidProvince
	case "street_address":
		a.Type = oidStreetAddress
	case "postal_code":
		a.Type = oidPostalCode
	default:
		// Check to see if it matches unknown_attribute_<hex string>
		matches := unknownNameRegex.FindAllString(ja.Name, -1)
		if len(matches) != 1 {
			break
		}
		// Parse the hex string as an attribute type
		if b, err := hex.DecodeString(matches[0]); err == nil {
			a.Type = make([]int, len(b))
			for idx, val := range b {
				a.Type[idx] = int(val)
			}
		}
	}
	return
}

func (n *Name) MarshalJSON() ([]byte, error) {
	var enc jsonName
	if n.CommonName != "" {
		enc.CommonName = &n.CommonName
	}
	attrs := n.ToRDNSequence()
	zlog.Info(len(attrs))
	for _, attrSet := range attrs {
		attrs := []AttributeTypeAndValue(attrSet)
		for _, a := range attrs {
			if reflect.DeepEqual(a.Type, oidCommonName) {
				continue
			}
			ja := toJSONAttribute(&a)
			enc.Attributes = append(enc.Attributes, ja)
		}
	}
	return json.Marshal(enc)
}

func (n *Name) UnmarshalJSON(b []byte) error {
	var enc jsonName
	if err := json.Unmarshal(b, &enc); err != nil {
		return err
	}
	if enc.CommonName != nil {
		n.CommonName = *enc.CommonName
	}
	return nil
}
