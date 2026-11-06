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
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

const (
	podIdentityEndpointIPv4       = "http://169.254.170.23/v1/credentials"
	podIdentityEndpointIPv6       = "http://[fd00:ec2::23]/v1/credentials"
	defaultCredentialRefreshLimit = 5 * time.Second
	defaultCredentialExpiryWindow = 5 * time.Minute
)

// credentialEnvironmentConflicts are credential and endpoint settings that
// must not influence a production provider which requires EKS Pod Identity.
var credentialEnvironmentConflicts = []string{
	"AWS_ACCESS_KEY_ID",
	"AWS_ACCESS_KEY",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SECRET_KEY",
	"AWS_SESSION_TOKEN",
	"AWS_WEB_IDENTITY_TOKEN_FILE",
	"AWS_ROLE_ARN",
	"AWS_PROFILE",
	"AWS_DEFAULT_PROFILE",
	"AWS_SHARED_CREDENTIALS_FILE",
	"AWS_CONFIG_FILE",
	"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
	"AWS_CONTAINER_AUTHORIZATION_TOKEN",
	"AWS_CA_BUNDLE",
	"AWS_DEFAULTS_MODE",
	"AWS_EC2_METADATA_SERVICE_ENDPOINT",
	"AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
	// Not AWS_REGION or AWS_DEFAULT_REGION: the EKS Pod Identity webhook sets
	// both on every pod it serves, and they pick no credentials. --region is
	// required in this mode and overrides them.
	"SSL_CERT_FILE",
	"SSL_CERT_DIR",
	"AWS_ENDPOINT_URL",
	"AWS_ENDPOINT_URL_STS",
	"AWS_ENDPOINT_URL_SECRETS_MANAGER",
}

// environmentDefaults are values of a conflicting setting that the image
// itself sets: the distroless base image (and ko's default base) points
// SSL_CERT_FILE at the system bundle.
var environmentDefaults = map[string]string{
	"SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
}

// podIdentityCredentials builds the credential provider explicitly instead of
// using the SDK's default chain, where static and web-identity credentials
// take precedence over container credentials.
func podIdentityCredentials() (*podIdentityCredentialProvider, error) {
	for _, name := range credentialEnvironmentConflicts {
		if v := os.Getenv(name); v != "" && v != environmentDefaults[name] {
			return nil, fmt.Errorf("%s must not be set when --require-pod-identity=true", name)
		}
	}

	endpoint := os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")
	tokenFile := os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
	if err := validatePodIdentityEnvironment(endpoint, tokenFile); err != nil {
		return nil, err
	}
	return newPodIdentityCredentials(endpoint, tokenFile, nil), nil
}

func validatePodIdentityEnvironment(endpoint, tokenFile string) error {
	if endpoint == "" {
		return fmt.Errorf("AWS_CONTAINER_CREDENTIALS_FULL_URI is not set")
	}
	if endpoint != podIdentityEndpointIPv4 && endpoint != podIdentityEndpointIPv6 {
		return fmt.Errorf("AWS_CONTAINER_CREDENTIALS_FULL_URI must be the EKS Pod Identity endpoint, got %q", endpoint)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("AWS_CONTAINER_CREDENTIALS_FULL_URI is not a valid EKS Pod Identity endpoint")
	}
	if tokenFile == "" {
		return fmt.Errorf("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE is not set")
	}
	if !filepath.IsAbs(tokenFile) {
		return fmt.Errorf("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE must be an absolute path")
	}
	return nil
}

type podIdentityCredentialProvider struct {
	credentials    aws.CredentialsProvider
	tokenFile      string
	refreshTimeout time.Duration

	mu                sync.Mutex
	lastErr           error
	refreshing        bool
	refreshStarted    time.Time
	credentialExpiry  time.Time
	credentialsExpire bool
}

func (p *podIdentityCredentialProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	refreshCtx, cancel := context.WithTimeout(ctx, p.refreshTimeout)
	defer cancel()

	p.mu.Lock()
	p.refreshing = true
	p.refreshStarted = time.Now()
	p.mu.Unlock()

	credentials, err := p.credentials.Retrieve(refreshCtx)
	p.mu.Lock()
	p.refreshing = false
	p.lastErr = err
	if err == nil {
		p.credentialExpiry = credentials.Expires
		p.credentialsExpire = credentials.CanExpire
	}
	p.mu.Unlock()
	return credentials, err
}

// HealthCheck verifies the local token projection and reports a failed or
// stalled credential refresh and credentials that have already expired.
func (p *podIdentityCredentialProvider) HealthCheck() error {
	if _, err := readPodIdentityToken(p.tokenFile); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.refreshing && now.Sub(p.refreshStarted) >= p.refreshTimeout {
		return fmt.Errorf("EKS Pod Identity credential refresh has exceeded %s", p.refreshTimeout)
	}
	if p.lastErr != nil {
		return p.lastErr
	}
	if p.credentialsExpire && !p.credentialExpiry.After(now) {
		return fmt.Errorf("EKS Pod Identity credentials expired at %s", p.credentialExpiry.UTC())
	}
	return nil
}

func newPodIdentityCredentials(endpoint, tokenFile string, client endpointcreds.HTTPClient) *podIdentityCredentialProvider {
	if client == nil {
		client = podIdentityHTTPClient()
	}
	provider := endpointcreds.New(endpoint, func(o *endpointcreds.Options) {
		o.HTTPClient = client
		o.AuthorizationTokenProvider = endpointcreds.TokenProviderFunc(func() (string, error) {
			return readPodIdentityToken(tokenFile)
		})
	})
	return &podIdentityCredentialProvider{
		credentials:    provider,
		tokenFile:      tokenFile,
		refreshTimeout: defaultCredentialRefreshLimit,
	}
}

func readPodIdentityToken(tokenFile string) (string, error) {
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("reading EKS Pod Identity authorization token: %w", err)
	}
	if len(data) == 0 {
		return "", fmt.Errorf("EKS Pod Identity authorization token is empty")
	}
	token := string(data)
	if strings.ContainsAny(token, "\r\n") {
		return "", fmt.Errorf("EKS Pod Identity authorization token contains a newline")
	}
	return token, nil
}

// matchesExpectedRole verifies the STS assumed-role identity returned by
// GetCallerIdentity against an operator-supplied IAM role ARN.
func matchesExpectedRole(expectedRoleARN, identityARN string) bool {
	expected, err := awsarn.Parse(expectedRoleARN)
	if err != nil || expected.Service != "iam" || !strings.HasPrefix(expected.Resource, "role/") {
		return false
	}
	identity, err := awsarn.Parse(identityARN)
	if err != nil || identity.Service != "sts" || identity.Partition != expected.Partition || identity.AccountID != expected.AccountID || !strings.HasPrefix(identity.Resource, "assumed-role/") {
		return false
	}
	resource := strings.TrimPrefix(identity.Resource, "assumed-role/")
	parts := strings.Split(resource, "/")
	return len(parts) == 2 && parts[0] == path.Base(strings.TrimPrefix(expected.Resource, "role/")) && parts[1] != ""
}

type timeoutCredentialsProvider struct {
	provider aws.CredentialsProvider
	timeout  time.Duration
}

func (p timeoutCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	return p.provider.Retrieve(timeoutCtx)
}

// credentialReadinessCheck actively retrieves through the SDK credential
// cache. A valid cached value returns locally; an expired value triggers a
// bounded refresh so a transient failure cannot leave readiness stuck false.
func credentialReadinessCheck(credentials aws.CredentialsProvider, state *podIdentityCredentialProvider) func() error {
	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), defaultCredentialRefreshLimit)
		defer cancel()
		if _, err := credentials.Retrieve(ctx); err != nil {
			return fmt.Errorf("refreshing EKS Pod Identity credentials: %w", err)
		}
		return state.HealthCheck()
	}
}

// requiredPodIdentityConfigOptions isolates both credentials and AWS service
// transport from ambient profiles, endpoint configuration, proxies and
// redirects.
func requiredPodIdentityConfigOptions(credentials aws.CredentialsProvider) []func(*config.LoadOptions) error {
	return []func(*config.LoadOptions) error{
		config.WithCredentialsProvider(credentials),
		config.WithCredentialsCacheOptions(func(o *aws.CredentialsCacheOptions) {
			o.ExpiryWindow = defaultCredentialExpiryWindow
			o.ExpiryWindowJitterFrac = 0.5
		}),
		config.WithSharedConfigFiles([]string{}),
		config.WithSharedCredentialsFiles([]string{}),
		config.WithDefaultsMode(aws.DefaultsModeStandard),
		config.WithEC2IMDSClientEnableState(imds.ClientDisabled),
		config.WithHTTPClient(hardenedAWSHTTPClient()),
	}
}

// podIdentityHTTPClient never sends the projected bearer token or returned
// credentials through an environment-configured HTTP proxy or redirect.
func podIdentityHTTPClient() *http.Client { return hardenedAWSHTTPClient() }

// hardenedAWSHTTPClient uses the standard TLS and timeout settings while
// removing ambient proxy and redirect behavior.
func hardenedAWSHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{
		Transport: transport,
		Timeout:   defaultCredentialRefreshLimit,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
