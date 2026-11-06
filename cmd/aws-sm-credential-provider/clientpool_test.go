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
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"plugins.go.ate.dev/credprovider-aws-secret-manager/internal/provider"
)

const readerRole = "arn:aws:iam::111122223333:role/ate-secrets-reader"

// fakeSTS records each AssumeRole call and answers with short-lived keys.
type fakeSTS struct {
	mu          sync.Mutex
	calls       []*sts.AssumeRoleInput
	expirations []time.Time
	block       bool
	expiration  time.Duration
}

func (f *fakeSTS) AssumeRole(ctx context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.mu.Lock()
	f.calls = append(f.calls, in)
	block := f.block
	expiration := f.expiration
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if expiration == 0 {
		expiration = time.Hour
	}
	expires := time.Now().Add(expiration)
	f.mu.Lock()
	f.expirations = append(f.expirations, expires)
	f.mu.Unlock()
	return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AKIDEXAMPLE"), SecretAccessKey: aws.String("example"),
		SessionToken: aws.String("example"), Expiration: aws.Time(expires),
	}}, nil
}

func ref(region string) provider.SecretRef {
	return provider.SecretRef{Account: "111122223333", Region: region, Name: "ate/team-a/x", Stage: "AWSCURRENT"}
}

func baseConfig() aws.Config {
	return aws.Config{Region: "us-west-2", Credentials: aws.AnonymousCredentials{}}
}

// Without a reader role, one client per region serves every atespace.
func TestClientPoolPerRegion(t *testing.T) {
	p := &clientPool{base: baseConfig()}
	a, err := p.client("team-a", "us-west-2")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := p.client("team-b", "us-west-2")
	c, _ := p.client("", "eu-west-1")
	if a != b {
		t.Error("two atespaces got different clients for one region, want one shared client")
	}
	if a == c {
		t.Error("two regions share a client")
	}
	if got := c.Options().Region; got != "eu-west-1" {
		t.Errorf("client region = %q, want eu-west-1", got)
	}
	if _, err := p.For("team-a", ref("us-west-2")); err != nil {
		t.Errorf("For: %v", err)
	}
}

// With a reader role, each atespace gets its own session, tagged with the
// atespace and named after it, shared by that atespace's regions.
func TestClientPoolPerAtespaceRole(t *testing.T) {
	fake := &fakeSTS{}
	p := &clientPool{base: baseConfig(), atespaceRoleARN: readerRole, sts: fake}
	if _, err := p.client("", "us-west-2"); err == nil {
		t.Fatal("a reader role without an atespace was accepted")
	}
	a, err := p.client("team-a", "us-west-2")
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := p.client("team-a", "eu-west-1")
	b, _ := p.client("team-b", "us-west-2")
	short, _ := p.client("x", "us-west-2")
	if a == b || a == a2 {
		t.Fatal("clients are shared across atespaces or regions")
	}
	for _, c := range []interface {
		Retrieve(context.Context) (aws.Credentials, error)
	}{a.Options().Credentials, a2.Options().Credentials, b.Options().Credentials, short.Options().Credentials} {
		if _, err := c.Retrieve(context.Background()); err != nil {
			t.Fatalf("Retrieve: %v", err)
		}
	}
	// team-a's two regions share one cached session: three AssumeRole calls.
	if len(fake.calls) != 3 {
		t.Fatalf("AssumeRole calls = %d, want 3 (team-a, team-b, x)", len(fake.calls))
	}
	want := map[string]string{"team-a": "team-a", "team-b": "team-b", "x": "atespace-x"}
	for _, in := range fake.calls {
		if aws.ToString(in.RoleArn) != readerRole {
			t.Errorf("RoleArn = %q, want %q", aws.ToString(in.RoleArn), readerRole)
		}
		if len(in.Tags) != 1 || aws.ToString(in.Tags[0].Key) != atespaceTagKey {
			t.Fatalf("Tags = %+v, want one %s tag", in.Tags, atespaceTagKey)
		}
		atespace := aws.ToString(in.Tags[0].Value)
		if got := aws.ToString(in.RoleSessionName); got != want[atespace] {
			t.Errorf("RoleSessionName for %q = %q, want %q", atespace, got, want[atespace])
		}
	}
}

func TestPerAtespaceAssumeRoleHasOperationDeadline(t *testing.T) {
	fake := &fakeSTS{block: true}
	p := &clientPool{
		base:                     baseConfig(),
		atespaceRoleARN:          readerRole,
		sts:                      fake,
		credentialRefreshTimeout: 25 * time.Millisecond,
	}
	client, err := p.client("team-a", "us-west-2")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := client.Options().Credentials.Retrieve(context.Background()); err == nil {
		t.Fatal("stalled AssumeRole returned no error")
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond || elapsed > time.Second {
		t.Fatalf("AssumeRole refresh lasted %v, want about 25ms", elapsed)
	}
}

func TestPerAtespaceCredentialsRefreshBeforeExpiration(t *testing.T) {
	fake := &fakeSTS{expiration: 2 * time.Minute}
	p := &clientPool{base: baseConfig(), atespaceRoleARN: readerRole, sts: fake}
	client, err := p.client("team-a", "us-west-2")
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.Options().Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	firstActualExpiry := fake.expirations[0]
	fake.mu.Unlock()
	advance := firstActualExpiry.Sub(first.Expires)
	if advance < 5*time.Minute/2 || advance > 5*time.Minute {
		t.Fatalf("effective expiry advanced by %v, want 2m30s to 5m", advance)
	}
	if !firstActualExpiry.After(time.Now()) {
		t.Fatal("test credentials were already actually expired")
	}
	if _, err := client.Options().Credentials.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	calls := len(fake.calls)
	fake.mu.Unlock()
	if calls != 2 {
		t.Fatalf("AssumeRole calls = %d, want a refresh while the first credentials remain valid", calls)
	}
}
