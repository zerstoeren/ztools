package pkix

import (
	"encoding/json"
	"testing"

	"github.com/zmap/ztools/zlog"
	. "gopkg.in/check.v1"
)

func TestJSON(t *testing.T) { TestingT(t) }

type JSONSuite struct {
	name *Name
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
}

func (s *JSONSuite) TestEncodeName(c *C) {
	var b []byte
	var err error
	b, err = json.Marshal(s.name)
	c.Assert(err, IsNil)
	zlog.Info(string(b))
	var dec jsonName
	err = json.Unmarshal(b, &dec)
	c.Assert(err, IsNil)
	c.Assert(dec.CommonName, NotNil)
	c.Check(*dec.CommonName, Equals, s.name.CommonName)
}
