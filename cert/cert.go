// Package cert fetches the root certificate for MitM proxy.
package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/golang/groupcache/singleflight"
	log "github.com/sirupsen/logrus"
)

// reference
// https://docs.mitmproxy.org/stable/concepts-certificates/
// https://github.com/mitmproxy/mitmproxy/blob/master/mitmproxy/certs.py

var errCaNotFound = errors.New("ca not found")

type Getter interface {
	GetCert(commonName string) (*tls.Certificate, error)
}

type CA struct {
	PrivateKey rsa.PrivateKey
	RootCert   x509.Certificate

	cacheMu sync.Mutex
	cache   *lru.Cache

	group *singleflight.Group
}

type Loader interface {
	Load() (*rsa.PrivateKey, *x509.Certificate, error)
}

func New(l Loader) (*CA, error) {
	key, cert, err := l.Load()
	if err != nil {
		return nil, err
	}
	return &CA{
		PrivateKey: *key,
		RootCert:   *cert,
		cache:      lru.New(100),
		group:      new(singleflight.Group),
	}, nil
}

func createCert() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() / 100000),
		Subject: pkix.Name{
			CommonName:   "mitmproxy",
			Organization: []string{"mitmproxy"},
		},
		NotBefore:             time.Now().Add(-time.Hour * 48),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 3),
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageTimeStamping,
			x509.ExtKeyUsageCodeSigning,
			x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
			x509.ExtKeyUsageMicrosoftServerGatedCrypto,
			x509.ExtKeyUsageNetscapeServerGatedCrypto,
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

type MemoryLoader struct{}

func (m *MemoryLoader) Load() (*rsa.PrivateKey, *x509.Certificate, error) {
	return createCert()
}

type PathLoader struct {
	StorePath string
}

func (p *PathLoader) Load() (*rsa.PrivateKey, *x509.Certificate, error) {
	if key, cert, err := p.load(); err != nil {
		if err != errCaNotFound {
			return nil, nil, err
		}
	} else {
		log.Debug("load root ca")
		return key, cert, nil
	}

	key, cert, err := p.create()
	if err != nil {
		return nil, nil, err
	}
	log.Debug("create root ca")
	return key, cert, nil
}

func NewPathLoader(path string) (*PathLoader, error) {
	if path == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(homeDir, ".mitmproxy")
	}

	if !filepath.IsAbs(path) {
		dir, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(dir, path)
	}

	stat, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(path, os.ModePerm)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	} else {
		if !stat.Mode().IsDir() {
			return nil, fmt.Errorf("path %v not a folder", path)
		}
	}

	return &PathLoader{StorePath: path}, nil
}

// The certificate and the private key in PEM format.
func (p *PathLoader) caFile() string {
	return filepath.Join(p.StorePath, "mitmproxy-ca.pem")
}

func (p *PathLoader) load() (*rsa.PrivateKey, *x509.Certificate, error) {
	caFile := p.caFile()
	stat, err := os.Stat(caFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, errCaNotFound
		}
		return nil, nil, err
	}

	if !stat.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%v not a file", caFile)
	}

	data, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, nil, err
	}

	keyDERBlock, data := pem.Decode(data)
	if keyDERBlock == nil {
		return nil, nil, fmt.Errorf("%v 中不存在 PRIVATE KEY", caFile)
	}
	certDERBlock, _ := pem.Decode(data)
	if certDERBlock == nil {
		return nil, nil, fmt.Errorf("%v 中不存在 CERTIFICATE", caFile)
	}

	var privateKey *rsa.PrivateKey
	key, err := x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		// fix #14
		if strings.Contains(err.Error(), "use ParsePKCS1PrivateKey instead") {
			privateKey, err = x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes)
			if err != nil {
				return nil, nil, err
			}
		} else {
			return nil, nil, err
		}
	} else {
		if v, ok := key.(*rsa.PrivateKey); ok {
			privateKey = v
		} else {
			return nil, nil, errors.New("found unknown rsa private key type in PKCS#8 wrapping")
		}
	}

	x509Cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, x509Cert, nil
}

func (p *PathLoader) create() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, cert, err := createCert()
	if err != nil {
		return nil, nil, err
	}

	if err := p.save(key, cert); err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func (p *PathLoader) saveTo(out io.Writer, key *rsa.PrivateKey, cert *x509.Certificate) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	err = pem.Encode(out, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		return err
	}

	return pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func (p *PathLoader) saveCertTo(out io.Writer, key *rsa.PrivateKey, cert *x509.Certificate) error {
	return pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func (p *PathLoader) save(key *rsa.PrivateKey, cert *x509.Certificate) error {
	file, err := os.Create(p.caFile())
	if err != nil {
		return err
	}
	defer file.Close()
	return p.saveTo(file, key, cert)
}

func (ca *CA) GetCert(commonName string) (*tls.Certificate, error) {
	ca.cacheMu.Lock()
	if val, ok := ca.cache.Get(commonName); ok {
		ca.cacheMu.Unlock()
		log.Debugf("ca GetCert: %v", commonName)
		return val.(*tls.Certificate), nil
	}
	ca.cacheMu.Unlock()

	val, err := ca.group.Do(commonName, func() (interface{}, error) {
		cert, err := ca.GenerateCert(commonName)
		if err == nil {
			ca.cacheMu.Lock()
			ca.cache.Add(commonName, cert)
			ca.cacheMu.Unlock()
		}
		return cert, err
	})

	if err != nil {
		return nil, err
	}

	return val.(*tls.Certificate), nil
}

// TODO: Should support multiple SubjectAltName.
func (ca *CA) GenerateCert(commonName string) (*tls.Certificate, error) {
	log.Debugf("ca DummyCert: %v", commonName)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() / 100000),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"mitmproxy"},
		},
		NotBefore:          time.Now().Add(-time.Hour * 48),
		NotAfter:           time.Now().Add(time.Hour * 24 * 365),
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	ip := net.ParseIP(commonName)
	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{commonName}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, &ca.RootCert, &ca.PrivateKey.PublicKey, &ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  &ca.PrivateKey,
	}

	return cert, nil
}
