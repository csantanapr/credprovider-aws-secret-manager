// Copyright 2026 The Agent Substrate Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package credbundle loads Kubernetes Pod Certificate credential bundles and PEM
// trust bundles. A credential bundle is one PEM file holding a PRIVATE KEY block
// and the CERTIFICATE chain, leaf first, with or without the root.
//
// It is the server-side subset of substrate's internal/credbundle, copied so
// this module depends only on substrate's public packages.
package credbundle

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
)

// Loader returns a tls.Config GetCertificate function serving the credential
// bundle at path. The parse is cached and redone only when the file changes, so
// a rotation is picked up on the next handshake.
func Loader(path string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := &certCache{path: path}
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return c.get()
	}
}

// PoolLoader returns a function yielding the trust pool in the PEM file at
// path, cached like Loader's. Call it per connection, e.g. from
// GetConfigForClient: a tls.Config's ClientCAs is fixed once in use, so a pool
// built at startup would miss a CA rotation.
func PoolLoader(path string) func() (*x509.CertPool, error) {
	c := &poolCache{path: path}
	return c.get
}

// certCache caches a credential bundle's parse with the file stat it came from.
type certCache struct {
	path string

	mu sync.Mutex
	// fi is the stat taken just before cert was parsed; cert is served while a
	// fresh stat matches it.
	fi   os.FileInfo
	cert *tls.Certificate
}

// get returns the cached bundle, re-parsing when the file's identity
// (os.SameFile), mtime or size has changed. The kubelet rotates projected
// volumes by swapping a symlink, which changes identity; mtime and size catch
// in-place rewrites.
//
// A change between the stat and the read stores newer content under the older
// stat, so the next call re-reads: the cache lags a rotation by at most one
// handshake. Errors are returned, never masked by the cache, and later calls
// retry.
func (c *certCache) get() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fi, err := os.Stat(c.path)
	if err != nil {
		return nil, fmt.Errorf("while getting file info for credential bundle %q: %w", c.path, err)
	}
	if c.cert != nil && os.SameFile(c.fi, fi) && fi.ModTime().Equal(c.fi.ModTime()) && fi.Size() == c.fi.Size() {
		return c.cert, nil
	}

	cert, err := Parse(c.path)
	if err != nil {
		return nil, err
	}
	c.fi, c.cert = fi, cert
	return cert, nil
}

// poolCache is certCache for a trust bundle.
type poolCache struct {
	path string

	mu   sync.Mutex
	fi   os.FileInfo
	pool *x509.CertPool
}

// get returns the cached trust pool, re-parsing as certCache.get does.
func (c *poolCache) get() (*x509.CertPool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fi, err := os.Stat(c.path)
	if err != nil {
		return nil, fmt.Errorf("while getting file info for trust bundle %q: %w", c.path, err)
	}
	if c.pool != nil && os.SameFile(c.fi, fi) && fi.ModTime().Equal(c.fi.ModTime()) && fi.Size() == c.fi.Size() {
		return c.pool, nil
	}

	pool, err := ParsePool(c.path)
	if err != nil {
		return nil, err
	}
	c.fi, c.pool = fi, pool
	return pool, nil
}

// Parse reads the single PKCS#8 private key and certificate chain from a
// credential bundle file, and verifies that the private key matches the leaf.
func Parse(bundlePath string) (*tls.Certificate, error) {
	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("while reading credential bundle: %w", err)
	}

	var certPEM, keyPEM []byte
	for {
		bundleBytes = bytes.TrimSpace(bundleBytes)
		if len(bundleBytes) == 0 {
			break
		}
		if !bytes.HasPrefix(bundleBytes, []byte("-----BEGIN ")) {
			return nil, fmt.Errorf("credential bundle contains malformed non-PEM data")
		}
		var block *pem.Block
		block, bundleBytes = pem.Decode(bundleBytes)
		if block == nil {
			return nil, fmt.Errorf("credential bundle contains malformed PEM data")
		}

		switch block.Type {
		case "CERTIFICATE":
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return nil, fmt.Errorf("while parsing certificate: %w", err)
			}
			certPEM = append(certPEM, pem.EncodeToMemory(block)...)
		case "PRIVATE KEY":
			if keyPEM != nil {
				return nil, fmt.Errorf("more than one PRIVATE KEY block found")
			}
			if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				return nil, fmt.Errorf("PRIVATE KEY block is not PKCS#8: %w", err)
			}
			keyPEM = pem.EncodeToMemory(block)
		default:
			return nil, fmt.Errorf("unknown PEM block type %q", block.Type)
		}
	}
	if len(bytes.TrimSpace(bundleBytes)) != 0 {
		return nil, fmt.Errorf("credential bundle contains malformed non-PEM data")
	}

	if keyPEM == nil {
		return nil, fmt.Errorf("no PRIVATE KEY block found")
	}
	if len(certPEM) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks found")
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate and private key pair: %w", err)
	}
	parsedChain := make([]*x509.Certificate, len(cert.Certificate))
	for i, der := range cert.Certificate {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("while parsing certificate %d: %w", i, err)
		}
		parsedChain[i] = parsed
		if i == 0 {
			cert.Leaf = parsed
			continue
		}
		if !parsed.BasicConstraintsValid || !parsed.IsCA {
			return nil, fmt.Errorf("certificate %d in serving chain is not a certificate authority", i)
		}
	}
	for i := 0; i+1 < len(parsedChain); i++ {
		if err := parsedChain[i].CheckSignatureFrom(parsedChain[i+1]); err != nil {
			return nil, fmt.Errorf("certificate %d is not signed by certificate %d: %w", i, i+1, err)
		}
	}
	return &cert, nil
}

// ParsePool reads a strict PEM trust bundle into a pool. Every block must be
// a parseable CA certificate; a partially valid bundle is rejected.
func ParsePool(path string) (*x509.CertPool, error) {
	pool, _, err := ParseTrustBundle(path)
	return pool, err
}

// ParseTrustBundle returns both the trust pool and parsed certificates so
// readiness can validate the current certificates' validity windows.
func ParseTrustBundle(path string) (*x509.CertPool, []*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("while reading trust bundle: %w", err)
	}
	pool := x509.NewCertPool()
	var certificates []*x509.Certificate
	for len(bytes.TrimSpace(pemBytes)) != 0 {
		pemBytes = bytes.TrimSpace(pemBytes)
		if !bytes.HasPrefix(pemBytes, []byte("-----BEGIN ")) {
			return nil, nil, fmt.Errorf("trust bundle %q contains malformed non-PEM data", path)
		}
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			return nil, nil, fmt.Errorf("trust bundle %q contains malformed non-PEM data", path)
		}
		pemBytes = rest
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("trust bundle %q contains PEM block type %q", path, block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing certificate in trust bundle %q: %w", path, err)
		}
		if !certificate.BasicConstraintsValid || !certificate.IsCA {
			return nil, nil, fmt.Errorf("trust bundle %q contains a certificate that is not a certificate authority", path)
		}
		pool.AddCert(certificate)
		certificates = append(certificates, certificate)
	}
	if len(certificates) == 0 {
		return nil, nil, fmt.Errorf("trust bundle %q contains no certificates", path)
	}
	return pool, certificates, nil
}
