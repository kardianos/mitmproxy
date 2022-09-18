package cert

import (
	"bytes"
	"io/ioutil"
	"reflect"
	"testing"
)

func TestGetStorePath(t *testing.T) {
	l, err := NewPathLoader("")
	if err != nil {
		t.Fatal(err)
	}
	if l.StorePath == "" {
		t.Fatal("should have path")
	}
}

func TestNewCA(t *testing.T) {
	l, err := NewPathLoader("")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := New(l)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 0)
	buf := bytes.NewBuffer(data)

	err = l.saveTo(buf, &ca.PrivateKey, &ca.RootCert)
	if err != nil {
		t.Fatal(err)
	}

	fileContent, err := ioutil.ReadFile(l.caFile())
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(fileContent, buf.Bytes()) {
		t.Fatal("pem content should equal")
	}
}
