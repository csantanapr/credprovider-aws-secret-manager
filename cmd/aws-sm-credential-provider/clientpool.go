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
	"errors"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"plugins.go.ate.dev/credprovider-aws-secret-manager/internal/provider"
)

// atespaceTagKey is the session tag the per-atespace reader role's policy
// matches, e.g. Resource arn:...:secret:ate/${aws:PrincipalTag/ate-atespace}/*.
const atespaceTagKey = "ate-atespace"

// clientPool holds one Secrets Manager client per region, or per
// (atespace, region) when atespaceRoleARN is set. Clients are created on first
// use and kept: the SDK refreshes their credentials itself.
type clientPool struct {
	base aws.Config
	// atespaceRoleARN, if set, is assumed (role chaining from the Pod Identity
	// session) once per atespace with an ate-atespace session tag, so IAM
	// enforces per-atespace access and CloudTrail names the atespace.
	atespaceRoleARN string
	// sts assumes atespaceRoleARN; an STS client in the provider's own region.
	sts stscreds.AssumeRoleAPIClient
	// credentialRefreshTimeout bounds the entire AssumeRole operation,
	// including retries. Zero selects the production default.
	credentialRefreshTimeout time.Duration

	mu      sync.Mutex
	clients map[[2]string]*secretsmanager.Client
	// creds holds one assumed-role session per atespace, shared by regions.
	creds map[string]*aws.CredentialsCache
}

// For returns the client that reads ref for atespace.
func (p *clientPool) For(atespace string, ref provider.SecretRef) (provider.SecretGetter, error) {
	return p.client(atespace, ref.Region)
}

func (p *clientPool) client(atespace, region string) (*secretsmanager.Client, error) {
	k := [2]string{"", region}
	if p.atespaceRoleARN != "" {
		if atespace == "" {
			return nil, errors.New("per-atespace role needs an atespace")
		}
		k[0] = atespace
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[k]; ok {
		return c, nil
	}
	cfg := p.base.Copy()
	cfg.Region = region
	if p.atespaceRoleARN != "" {
		cc, ok := p.creds[atespace]
		if !ok {
			timeout := p.credentialRefreshTimeout
			if timeout <= 0 {
				timeout = defaultCredentialRefreshLimit
			}
			assume := stscreds.NewAssumeRoleProvider(p.sts, p.atespaceRoleARN,
				func(o *stscreds.AssumeRoleOptions) {
					o.RoleSessionName = sessionName(atespace)
					o.Tags = []ststypes.Tag{{Key: aws.String(atespaceTagKey), Value: aws.String(atespace)}}
				})
			cc = aws.NewCredentialsCache(timeoutCredentialsProvider{provider: assume, timeout: timeout},
				func(o *aws.CredentialsCacheOptions) {
					o.ExpiryWindow = defaultCredentialExpiryWindow
					o.ExpiryWindowJitterFrac = 0.5
				})
			if p.creds == nil {
				p.creds = map[string]*aws.CredentialsCache{}
			}
			p.creds[atespace] = cc
		}
		cfg.Credentials = cc
	}
	c := secretsmanager.NewFromConfig(cfg)
	if p.clients == nil {
		p.clients = map[[2]string]*secretsmanager.Client{}
	}
	p.clients[k] = c
	return c, nil
}

// sessionName is the RoleSessionName CloudTrail shows: the atespace, a DNS
// label of at most 63 characters, padded to the 2-character minimum.
func sessionName(atespace string) string {
	if len(atespace) < 2 {
		return "atespace-" + atespace
	}
	return atespace
}
