package pkix

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/zmap/ztools/zlog"
	. "gopkg.in/check.v1"
)

func TestJSON(t *testing.T) { TestingT(t) }

type JSONSuite struct {
	name *Name
	ext  *Extension
}

var _ = Suite(&JSONSuite{})

func (s *JSONSuite) SetUpTest(c *C) {
	s.name = new(Name)
	s.name.CommonName = "davidadrian.org"
	s.name.SerialNumber = "12345678910"
	s.name.Country = []string{"US"}
	s.name.Organization = []string{"University of Michigan"}
	s.name.Locality = []string{"Ann Arbor"}
	s.name.Province = []string{"MI"}

	s.ext = new(Extension)
	s.ext.Id = oidCommonName
	s.ext.Critical = true
	s.ext.Value = []byte{1, 2, 3, 4, 5, 6, 7, 8}
}

func (s *JSONSuite) TestEncodeDecodeName(c *C) {
	var encoded, reencoded []byte
	var err error
	encoded, err = json.Marshal(s.name)
	c.Assert(err, IsNil)
	zlog.Info(string(encoded))
	var dec jsonName
	err = json.Unmarshal(encoded, &dec)
	c.Assert(err, IsNil)
	c.Assert(dec.CommonName, NotNil)
	c.Check(*dec.CommonName, Equals, s.name.CommonName)
	reencoded, err = json.Marshal(&dec)
	c.Assert(err, IsNil)
	zlog.Info(string(reencoded))
	c.Check(reencoded, DeepEquals, encoded)
}

func (s *JSONSuite) TestEncodeDecodeExtension(c *C) {
	b, err := json.Marshal(s.ext)
	c.Assert(err, IsNil)
	fmt.Println(string(b))
}
