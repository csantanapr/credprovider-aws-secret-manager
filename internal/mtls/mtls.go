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

// Package mtls builds the provider's mutual-TLS server credentials. A caller
// must chain to the client trust bundle and carry the expected URI SAN, so no
// other workload that CA trusts can fetch secrets. Both files reload on
// rotation without a restart.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"time"

	"google.golang.org/grpc/credentials"

	"plugins.go.ate.dev/credprovider-aws-secret-manager/internal/credbundle"
)

// Config names the files and caller identity ServerCredentials serves with.
type Config struct {
	// ServerBundle is the serving credential bundle (PKCS#8 key and chain).
	ServerBundle string
	// ClientCAFile is the trust bundle a caller's certificate must chain to.
	ClientCAFile string
	// CallerIdentity is the URI SAN a caller's certificate must carry.
	CallerIdentity string
}

// ServerCredentials returns gRPC server credentials requiring TLS 1.3 and a
// client certificate satisfying cfg. It fails if a field is empty or either
// bundle is unreadable, so a missing projection fails startup rather than
// leaving a Ready pod that refuses every connection.
func ServerCredentials(cfg Config) (credentials.TransportCredentials, error) {
	switch {
	case cfg.ServerBundle == "":
		return nil, errors.New("a server credential bundle is required")
	case cfg.ClientCAFile == "":
		return nil, errors.New("a client trust bundle is required")
	case cfg.CallerIdentity == "":
		return nil, errors.New("a caller identity is required")
	case !validSPIFFEID(cfg.CallerIdentity):
		return nil, fmt.Errorf("caller identity %q is not a canonical SPIFFE ID", cfg.CallerIdentity)
	}

	loadPool := credbundle.PoolLoader(cfg.ClientCAFile)
	if _, err := loadPool(); err != nil {
		return nil, err
	}
	serverCert := credbundle.Loader(cfg.ServerBundle)
	if _, err := serverCert(nil); err != nil {
		return nil, err
	}
	verifySAN := verifyCallerSAN(cfg.CallerIdentity)

	// A per-connection config picks up a rotated client CA without a restart.
	return credentials.NewTLS(&tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			pool, err := loadPool()
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion:       tls.VersionTLS13,
				GetCertificate:   serverCert,
				ClientAuth:       tls.RequireAndVerifyClientCert,
				ClientCAs:        pool,
				VerifyConnection: verifySAN,
			}, nil
		},
	}), nil
}

// verifyCallerSAN returns a VerifyConnection callback requiring exactly the
// expected URI SAN. A SPIFFE X.509-SVID contains exactly one URI SAN.
func verifyCallerSAN(expectedSAN string) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("client certificate is required")
		}
		leaf := state.PeerCertificates[0]
		if len(leaf.URIs) != 1 || leaf.URIs[0].String() != expectedSAN {
			return fmt.Errorf("client certificate must carry exactly the expected caller URI SAN %q", expectedSAN)
		}
		return nil
	}
}

func validSPIFFEID(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "spiffe" && u.Host != "" && u.User == nil &&
		u.RawQuery == "" && u.Fragment == "" && u.Path != "" && u.EscapedPath() == u.Path && u.String() == raw
}

// HealthCheck returns a readiness dependency that follows certificate and
// trust-bundle rotations and rejects malformed, non-CA, expired, or
// not-yet-valid certificates.
func HealthCheck(cfg Config) func() error {
	serverCert := credbundle.Loader(cfg.ServerBundle)
	return func() error {
		cert, err := serverCert(nil)
		if err != nil {
			return fmt.Errorf("server credential bundle: %w", err)
		}
		now := time.Now()
		for i, der := range cert.Certificate {
			parsed, err := x509.ParseCertificate(der)
			if err != nil {
				return fmt.Errorf("server certificate %d: %w", i, err)
			}
			if now.Before(parsed.NotBefore) || now.After(parsed.NotAfter) {
				return fmt.Errorf("server certificate %d is not valid at %s (valid from %s to %s)", i, now.UTC(), parsed.NotBefore.UTC(), parsed.NotAfter.UTC())
			}
		}
		_, trustCertificates, err := credbundle.ParseTrustBundle(cfg.ClientCAFile)
		if err != nil {
			return fmt.Errorf("client trust bundle: %w", err)
		}
		for i, certificate := range trustCertificates {
			if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
				return fmt.Errorf("client trust certificate %d is not valid at %s (valid from %s to %s)", i, now.UTC(), certificate.NotBefore.UTC(), certificate.NotAfter.UTC())
			}
		}
		return nil
	}
}
