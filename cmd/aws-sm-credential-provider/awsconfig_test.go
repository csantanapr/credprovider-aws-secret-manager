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

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

type credentialsHTTPClient struct {
	t       *testing.T
	wantJWT string
}

func (c credentialsHTTPClient) Do(req *http.Request) (*http.Response, error) {
	c.t.Helper()
	if got := req.Header.Get("Authorization"); got != c.wantJWT {
		c.t.Fatalf("Authorization = %q, want Pod Identity token", got)
	}
	body := `{"AccessKeyId":"PODIDENTITYKEY","SecretAccessKey":"pod-secret","Token":"pod-session","Expiration":"2099-01-01T00:00:00Z"}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func TestValidatePodIdentityEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name, endpoint, tokenFile string
		wantErr                   bool
	}{
		{name: "IPv4", endpoint: podIdentityEndpointIPv4, tokenFile: "/var/run/pod-token"},
		{name: "IPv6", endpoint: podIdentityEndpointIPv6, tokenFile: "/var/run/pod-token"},
		{name: "missing endpoint", tokenFile: "/var/run/pod-token", wantErr: true},
		{name: "arbitrary loopback", endpoint: "http://127.0.0.1/credentials", tokenFile: "/var/run/pod-token", wantErr: true},
		{name: "endpoint query", endpoint: podIdentityEndpointIPv4 + "?redirect=1", tokenFile: "/var/run/pod-token", wantErr: true},
		{name: "missing token file", endpoint: podIdentityEndpointIPv4, wantErr: true},
		{name: "relative token file", endpoint: podIdentityEndpointIPv4, tokenFile: "token", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePodIdentityEnvironment(tc.endpoint, tc.tokenFile)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validatePodIdentityEnvironment() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestExplicitPodIdentityCredentialsIgnoreStaticEnvironmentCredentials(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("pod-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "STATICKEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "static-secret")

	provider := newPodIdentityCredentials(podIdentityEndpointIPv4, tokenFile, credentialsHTTPClient{t: t, wantJWT: "pod-jwt"})
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("us-west-2"), config.WithCredentialsProvider(provider))
	if err != nil {
		t.Fatal(err)
	}
	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessKeyID != "PODIDENTITYKEY" {
		t.Fatalf("AccessKeyID = %q, want the explicit Pod Identity credential", creds.AccessKeyID)
	}
}

func TestPodIdentityCredentialsRejectConflictingEnvironment(t *testing.T) {
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", podIdentityEndpointIPv4)
	t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "/var/run/pod-token")
	for _, name := range credentialEnvironmentConflicts {
		t.Run(name, func(t *testing.T) {
			for _, other := range credentialEnvironmentConflicts {
				t.Setenv(other, "")
			}
			t.Setenv(name, "set")
			if _, err := podIdentityCredentials(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("podIdentityCredentials() error = %v, want conflict for %s", err, name)
			}
		})
	}
}

// The environment the EKS Pod Identity webhook injects into a pod.
func TestPodIdentityCredentialsAcceptWebhookEnvironment(t *testing.T) {
	for _, name := range credentialEnvironmentConflicts {
		t.Setenv(name, "")
	}
	t.Setenv("AWS_STS_REGIONAL_ENDPOINTS", "regional")
	t.Setenv("AWS_DEFAULT_REGION", "us-west-2")
	t.Setenv("AWS_REGION", "us-west-2")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", podIdentityEndpointIPv4)
	t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token")
	if _, err := podIdentityCredentials(); err != nil {
		t.Fatalf("podIdentityCredentials() error = %v", err)
	}
}

// The distroless base image sets SSL_CERT_FILE to the system bundle; any
// other bundle is still refused.
func TestPodIdentityCredentialsCertFile(t *testing.T) {
	for _, name := range credentialEnvironmentConflicts {
		t.Setenv(name, "")
	}
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", podIdentityEndpointIPv4)
	t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "/var/run/pod-token")
	t.Setenv("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")
	if _, err := podIdentityCredentials(); err != nil {
		t.Fatalf("system bundle: %v", err)
	}
	t.Setenv("SSL_CERT_FILE", "/tmp/evil-ca.pem")
	if _, err := podIdentityCredentials(); err == nil || !strings.Contains(err.Error(), "SSL_CERT_FILE") {
		t.Fatalf("other bundle: error = %v, want a SSL_CERT_FILE conflict", err)
	}
}

func TestMatchesExpectedRole(t *testing.T) {
	for _, tc := range []struct {
		name, expected, identity string
		want                     bool
	}{
		{name: "match", expected: "arn:aws:iam::111122223333:role/aws-sm-credential-provider", identity: "arn:aws:sts::111122223333:assumed-role/aws-sm-credential-provider/session", want: true},
		{name: "role path", expected: "arn:aws:iam::111122223333:role/providers/aws-sm-credential-provider", identity: "arn:aws:sts::111122223333:assumed-role/aws-sm-credential-provider/session", want: true},
		{name: "wrong account", expected: "arn:aws:iam::111122223333:role/aws-sm-credential-provider", identity: "arn:aws:sts::444455556666:assumed-role/aws-sm-credential-provider/session"},
		{name: "wrong role", expected: "arn:aws:iam::111122223333:role/aws-sm-credential-provider", identity: "arn:aws:sts::111122223333:assumed-role/admin/session"},
		{name: "federated user with matching name", expected: "arn:aws:iam::111122223333:role/federated-user", identity: "arn:aws:sts::111122223333:federated-user/alice"},
		{name: "STS resource without assumed-role prefix", expected: "arn:aws:iam::111122223333:role/example", identity: "arn:aws:sts::111122223333:example/session"},
		{name: "user", expected: "arn:aws:iam::111122223333:role/aws-sm-credential-provider", identity: "arn:aws:iam::111122223333:user/example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesExpectedRole(tc.expected, tc.identity); got != tc.want {
				t.Fatalf("matchesExpectedRole() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPodIdentityHTTPClientDisablesProxyAndRedirects(t *testing.T) {
	client := podIdentityHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("Pod Identity HTTP transport has a proxy function")
	}
	if client.Timeout != defaultCredentialRefreshLimit {
		t.Fatalf("HTTP timeout = %v, want %v", client.Timeout, defaultCredentialRefreshLimit)
	}
	if client.CheckRedirect == nil {
		t.Fatal("Pod Identity HTTP client permits default redirects")
	}
	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(req, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect = %v, want http.ErrUseLastResponse", err)
	}
}

func TestRequiredPodIdentityConfigOptionsIsolateAWSConfiguration(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("pod-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := newPodIdentityCredentials(podIdentityEndpointIPv4, tokenFile, credentialsHTTPClient{t: t, wantJWT: "pod-jwt"})
	var load config.LoadOptions
	for _, option := range requiredPodIdentityConfigOptions(provider) {
		if err := option(&load); err != nil {
			t.Fatal(err)
		}
	}
	if load.Credentials != provider {
		t.Fatal("required configuration did not retain the explicit Pod Identity provider")
	}
	if load.SharedConfigFiles == nil || len(load.SharedConfigFiles) != 0 {
		t.Fatalf("SharedConfigFiles = %#v, want an explicit empty list", load.SharedConfigFiles)
	}
	if load.SharedCredentialsFiles == nil || len(load.SharedCredentialsFiles) != 0 {
		t.Fatalf("SharedCredentialsFiles = %#v, want an explicit empty list", load.SharedCredentialsFiles)
	}
	if load.DefaultsModeOptions.Mode != "standard" {
		t.Fatalf("DefaultsMode = %q, want standard", load.DefaultsModeOptions.Mode)
	}
	if load.EC2IMDSClientEnableState != imds.ClientDisabled {
		t.Fatalf("EC2IMDSClientEnableState = %v, want disabled", load.EC2IMDSClientEnableState)
	}
	client, ok := load.HTTPClient.(*http.Client)
	if !ok {
		t.Fatalf("HTTPClient = %T, want *http.Client", load.HTTPClient)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || client.CheckRedirect == nil {
		t.Fatal("AWS service HTTP client permits a proxy or redirects")
	}
}

func TestPodIdentityCredentialHealthTracksTokenProjection(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("pod-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := newPodIdentityCredentials(podIdentityEndpointIPv4, tokenFile, credentialsHTTPClient{t: t, wantJWT: "pod-jwt"})
	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := provider.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck(valid) = %v", err)
	}
	if err := os.WriteFile(tokenFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := provider.HealthCheck(); err == nil {
		t.Fatal("HealthCheck accepted an empty Pod Identity token")
	}
	if err := os.Remove(tokenFile); err != nil {
		t.Fatal(err)
	}
	if err := provider.HealthCheck(); err == nil {
		t.Fatal("HealthCheck accepted a missing Pod Identity token")
	}
}

func TestRequiredPodIdentityConfigIgnoresDefaultSharedEndpoint(t *testing.T) {
	home := t.TempDir()
	awsDir := filepath.Join(home, ".aws")
	if err := os.MkdirAll(awsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(awsDir, "config"), []byte("[default]\nendpoint_url = https://attacker.invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("pod-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := newPodIdentityCredentials(podIdentityEndpointIPv4, tokenFile, credentialsHTTPClient{t: t, wantJWT: "pod-jwt"})
	options := requiredPodIdentityConfigOptions(provider)
	options = append(options, config.WithRegion("us-west-2"))
	cfg, err := config.LoadDefaultConfig(context.Background(), options...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BaseEndpoint != nil {
		t.Fatalf("BaseEndpoint = %q, want the default shared profile ignored", *cfg.BaseEndpoint)
	}
}

type credentialsProviderFunc func(context.Context) (aws.Credentials, error)

func (f credentialsProviderFunc) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return f(ctx)
}

func TestPodIdentityCredentialRefreshHasHardDeadline(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("pod-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := &podIdentityCredentialProvider{
		credentials: credentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			<-ctx.Done()
			return aws.Credentials{}, ctx.Err()
		}),
		tokenFile:      tokenFile,
		refreshTimeout: 25 * time.Millisecond,
	}
	start := time.Now()
	if _, err := provider.Retrieve(context.Background()); err == nil {
		t.Fatal("stalled credential refresh returned no error")
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond || elapsed > time.Second {
		t.Fatalf("credential refresh lasted %v, want about 25ms", elapsed)
	}
	if err := provider.HealthCheck(); err == nil {
		t.Fatal("readiness ignored the failed credential refresh")
	}
}

func TestPodIdentityCredentialHealthRejectsExpiredCredentials(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("pod-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := &podIdentityCredentialProvider{
		credentials: credentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "expired", SecretAccessKey: "expired", CanExpire: true, Expires: time.Now().Add(-time.Minute)}, nil
		}),
		tokenFile:      tokenFile,
		refreshTimeout: time.Second,
	}
	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := provider.HealthCheck(); err == nil {
		t.Fatal("readiness accepted expired credentials")
	}
}

func TestCredentialReadinessRecoversWithoutApplicationTraffic(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("pod-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	state := &podIdentityCredentialProvider{
		credentials: credentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			calls++
			if calls == 1 {
				return aws.Credentials{}, fmt.Errorf("transient refresh failure")
			}
			return aws.Credentials{AccessKeyID: "recovered", SecretAccessKey: "recovered", CanExpire: true, Expires: time.Now().Add(time.Hour)}, nil
		}),
		tokenFile:      tokenFile,
		refreshTimeout: time.Second,
	}
	cache := aws.NewCredentialsCache(state)
	check := credentialReadinessCheck(cache, state)
	if err := check(); err == nil {
		t.Fatal("first readiness check ignored the credential refresh failure")
	}
	if err := check(); err != nil {
		t.Fatalf("second readiness check did not recover credentials: %v", err)
	}
	if calls != 2 {
		t.Fatalf("credential refresh calls = %d, want 2", calls)
	}
}

func TestCredentialReadinessRecoversAfterCachedExpiration(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("pod-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	state := &podIdentityCredentialProvider{
		credentials: credentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			calls++
			expiresIn := time.Hour
			if calls == 1 {
				expiresIn = 20 * time.Millisecond
			}
			return aws.Credentials{
				AccessKeyID: "credential", SecretAccessKey: "credential", CanExpire: true,
				Expires: time.Now().Add(expiresIn),
			}, nil
		}),
		tokenFile:      tokenFile,
		refreshTimeout: time.Second,
	}
	cache := aws.NewCredentialsCache(state)
	if _, err := cache.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if err := credentialReadinessCheck(cache, state)(); err != nil {
		t.Fatalf("readiness did not recover expired cached credentials: %v", err)
	}
	if calls != 2 {
		t.Fatalf("credential refresh calls = %d, want 2", calls)
	}
}
