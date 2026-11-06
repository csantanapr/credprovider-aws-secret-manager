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

package provider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"go.ate.dev/substrate/api/credprovider/v1"
)

const (
	acct     = "111122223333"
	otherAcc = "444455556666"
	actorA   = "spiffe://substrate-actor.local/actor/team-a/agent-1"
	actorB   = "spiffe://substrate-actor.local/actor/team-b/agent-1"
)

// fakeSM answers GetSecretValue from a map of secret ID -> output or error.
type fakeSM struct {
	calls atomic.Int32
	delay time.Duration
	mu    sync.Mutex
	last  *secretsmanager.GetSecretValueInput
	out   map[string]*secretsmanager.GetSecretValueOutput
	err   map[string]error
}

func (f *fakeSM) GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.calls.Add(1)
	f.mu.Lock()
	f.last = in
	f.mu.Unlock()
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	id := aws.ToString(in.SecretId)
	if err := f.err[id]; err != nil {
		return nil, err
	}
	if o := f.out[id]; o != nil {
		copy := *o
		if copy.VersionId == nil && in.VersionId != nil {
			copy.VersionId = aws.String(aws.ToString(in.VersionId))
		}
		if len(copy.VersionStages) == 0 && in.VersionStage != nil {
			copy.VersionStages = []string{aws.ToString(in.VersionStage)}
		}
		return &copy, nil
	}
	return nil, &smithy.GenericAPIError{Code: "ResourceNotFoundException", Message: "Secrets Manager can't find the specified secret."}
}

func arn(account, name string) *string {
	return aws.String("arn:aws:secretsmanager:us-west-2:" + account + ":secret:" + name + "-AbCdEf")
}

func testPolicy(t *testing.T) *Authorizer {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	yamlText := `policies:
- atespace: team-a
  allowedSecrets:
  - account: "` + acct + `"
    region: us-west-2
    namePrefix: ate/team-a/
  - account: "` + otherAcc + `"
    region: us-west-2
    name: shared/github
`
	if err := os.WriteFile(p, []byte(yamlText), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := LoadAuthorizer(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func newTestServer(t *testing.T, sm *fakeSM, cfg CacheConfig, scope bool) *Server {
	getters := func(string, SecretRef) (SecretGetter, error) { return sm, nil }
	return NewServer(getters, testPolicy(t), NewCache(cfg, time.Second), acct, scope)
}

func uri(account, name, tail string) string {
	return "ate-secret://secretsmanager.amazonaws.com/accounts/" + account + "/regions/us-west-2/secrets/" + name + tail
}

func defaultSM() *fakeSM {
	return &fakeSM{out: map[string]*secretsmanager.GetSecretValueOutput{
		"ate/team-a/github": {Name: aws.String("ate/team-a/github"), ARN: arn(acct, "ate/team-a/github"), SecretString: aws.String(`{"token":"ghp_example","n":1}`)},
		"ate/team-a/raw":    {Name: aws.String("ate/team-a/raw"), ARN: arn(acct, "ate/team-a/raw"), SecretString: aws.String("plain-token")},
		"ate/team-a/bin":    {Name: aws.String("ate/team-a/bin"), ARN: arn(acct, "ate/team-a/bin"), SecretBinary: []byte{0x01, 0x02}},
		"arn:aws:secretsmanager:us-west-2:" + otherAcc + ":secret:shared/github": {Name: aws.String("shared/github"), ARN: arn(otherAcc, "shared/github"), SecretString: aws.String("x-acct")},
		// A name that Secrets Manager resolved to some other secret.
		"ate/team-a/confused": {Name: aws.String("ate/team-a/other"), ARN: arn(acct, "ate/team-a/other"), SecretString: aws.String("wrong")},
		// A sibling whose ARN shares the requested secret's old prefix check.
		"ate/team-a/foo":           {Name: aws.String("ate/team-a/foo-extra"), ARN: arn(acct, "ate/team-a/foo-extra"), SecretString: aws.String("wrong")},
		"ate/team-a/wrong-stage":   {Name: aws.String("ate/team-a/wrong-stage"), ARN: arn(acct, "ate/team-a/wrong-stage"), VersionStages: []string{"AWSPREVIOUS"}, SecretString: aws.String("wrong")},
		"ate/team-a/wrong-version": {Name: aws.String("ate/team-a/wrong-version"), ARN: arn(acct, "ate/team-a/wrong-version"), VersionId: aws.String("aaaaaaaa-1111-2222-3333-444455556666"), SecretString: aws.String("wrong")},
	}, err: map[string]error{
		"ate/team-a/throttled": &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"},
		"ate/team-a/denied":    &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"},
		"ate/team-a/kms":       &smithy.GenericAPIError{Code: "DecryptionFailure", Message: "kms"},
		"ate/team-a/deleting":  &smithy.GenericAPIError{Code: "InvalidRequestException", Message: "marked for deletion"},
		"ate/team-a/agentdown": errors.New("failed to refresh cached credentials, operation error ec2imds"),
		// The per-atespace reader role refused sts:AssumeRole: the SDK wraps
		// STS's error in the GetSecretValue failure.
		"ate/team-a/reader-denied": fmt.Errorf("operation error Secrets Manager: GetSecretValue, failed to refresh cached credentials, %w",
			&smithy.OperationError{ServiceID: "STS", OperationName: "AssumeRole",
				Err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized to perform: sts:AssumeRole"}}),
	}}
}

func TestFetchSecret(t *testing.T) {
	cases := []struct {
		name, uri, actor string
		want             string
		code             codes.Code
	}{
		{"key", uri(acct, "ate/team-a/github", "/stages/AWSCURRENT/keys/token"), actorA, "ghp_example", codes.OK},
		{"raw string", uri(acct, "ate/team-a/raw", "/stages/AWSCURRENT"), actorA, "plain-token", codes.OK},
		{"binary", uri(acct, "ate/team-a/bin", "/stages/AWSCURRENT"), actorA, "\x01\x02", codes.OK},
		{"cross-account by ARN", uri(otherAcc, "shared/github", "/stages/AWSCURRENT"), actorA, "x-acct", codes.OK},
		{"other atespace denied", uri(acct, "ate/team-a/github", "/stages/AWSCURRENT/keys/token"), actorB, "", codes.PermissionDenied},
		{"outside prefix denied", uri(acct, "ate/team-ab/github", "/stages/AWSCURRENT"), actorA, "", codes.PermissionDenied},
		{"bad actor", uri(acct, "ate/team-a/github", "/stages/AWSCURRENT"), "spiffe://cluster.local/ns/x/sa/y", "", codes.PermissionDenied},
		{"bad uri", "ate-secret://secretsmanager.amazonaws.com/x/y", actorA, "", codes.InvalidArgument},
		{"missing", uri(acct, "ate/team-a/nope", "/stages/AWSCURRENT"), actorA, "", codes.NotFound},
		{"missing key", uri(acct, "ate/team-a/github", "/stages/AWSCURRENT/keys/nope"), actorA, "", codes.NotFound},
		{"non-string key", uri(acct, "ate/team-a/github", "/stages/AWSCURRENT/keys/n"), actorA, "", codes.FailedPrecondition},
		{"not json", uri(acct, "ate/team-a/raw", "/stages/AWSCURRENT/keys/x"), actorA, "", codes.FailedPrecondition},
		{"throttled", uri(acct, "ate/team-a/throttled", "/stages/AWSCURRENT"), actorA, "", codes.Unavailable},
		{"iam denied", uri(acct, "ate/team-a/denied", "/stages/AWSCURRENT"), actorA, "", codes.PermissionDenied},
		{"kms denied", uri(acct, "ate/team-a/kms", "/stages/AWSCURRENT"), actorA, "", codes.PermissionDenied},
		{"scheduled for deletion", uri(acct, "ate/team-a/deleting", "/stages/AWSCURRENT"), actorA, "", codes.FailedPrecondition},
		{"credentials unavailable", uri(acct, "ate/team-a/agentdown", "/stages/AWSCURRENT"), actorA, "", codes.Unavailable},
		{"resolved to other secret", uri(acct, "ate/team-a/confused", "/stages/AWSCURRENT"), actorA, "", codes.PermissionDenied},
		{"prefix-colliding sibling denied", uri(acct, "ate/team-a/foo", "/stages/AWSCURRENT"), actorA, "", codes.PermissionDenied},
		{"wrong stage denied", uri(acct, "ate/team-a/wrong-stage", "/stages/AWSCURRENT"), actorA, "", codes.PermissionDenied},
		{"wrong version denied", uri(acct, "ate/team-a/wrong-version", "/versions/0d0a8f6e-1111-2222-3333-444455556666"), actorA, "", codes.PermissionDenied},
		{"reader role denied", uri(acct, "ate/team-a/reader-denied", "/stages/AWSCURRENT"), actorA, "", codes.PermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sm := defaultSM()
			s := newTestServer(t, sm, CacheConfig{StageTTL: time.Minute}, false)
			resp, err := s.FetchSecret(context.Background(), &credprovider.FetchSecretRequest{Uri: tc.uri, ActorSpiffeId: tc.actor})
			if got := status.Code(err); got != tc.code {
				t.Fatalf("code = %v (%v), want %v", got, err, tc.code)
			}
			if tc.code == codes.OK && string(resp.GetOpaqueBytes()) != tc.want {
				t.Fatalf("value = %q, want %q", resp.GetOpaqueBytes(), tc.want)
			}
			if (tc.code == codes.PermissionDenied && tc.name != "iam denied" && tc.name != "kms denied" && tc.name != "resolved to other secret" && tc.name != "prefix-colliding sibling denied" && tc.name != "wrong stage denied" && tc.name != "wrong version denied" && tc.name != "reader role denied") || tc.code == codes.InvalidArgument {
				if n := sm.calls.Load(); n != 0 {
					t.Fatalf("denied before Secrets Manager, but it was called %d times", n)
				}
			}
		})
	}
}

func TestStageAndVersionPassedThrough(t *testing.T) {
	sm := defaultSM()
	s := newTestServer(t, sm, CacheConfig{}, false)
	_, _ = s.FetchSecret(context.Background(), &credprovider.FetchSecretRequest{
		Uri: uri(acct, "ate/team-a/github", "/stages/AWSPREVIOUS"), ActorSpiffeId: actorA})
	if aws.ToString(sm.last.VersionStage) != "AWSPREVIOUS" || sm.last.VersionId != nil {
		t.Fatalf("stage not passed: %+v", sm.last)
	}
	_, _ = s.FetchSecret(context.Background(), &credprovider.FetchSecretRequest{
		Uri: uri(acct, "ate/team-a/github", "/versions/0d0a8f6e-1111-2222-3333-444455556666"), ActorSpiffeId: actorA})
	if aws.ToString(sm.last.VersionId) != "0d0a8f6e-1111-2222-3333-444455556666" || sm.last.VersionStage != nil {
		t.Fatalf("version not passed: %+v", sm.last)
	}
}

func TestCacheHitsCoalescesAndExpires(t *testing.T) {
	sm := defaultSM()
	sm.delay = 50 * time.Millisecond
	s := newTestServer(t, sm, CacheConfig{StageTTL: time.Minute}, false)
	now := time.Now()
	s.cache.now = func() time.Time { return now }
	req := &credprovider.FetchSecretRequest{Uri: uri(acct, "ate/team-a/github", "/stages/AWSCURRENT/keys/token"), ActorSpiffeId: actorA}

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.FetchSecret(context.Background(), req); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := sm.calls.Load(); n != 1 {
		t.Fatalf("50 concurrent requests made %d GetSecretValue calls, want 1", n)
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.FetchSecret(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if n := sm.calls.Load(); n != 2 {
		t.Fatalf("after TTL: %d calls, want 2", n)
	}
}

func TestCacheNeverCachesTransientErrors(t *testing.T) {
	sm := defaultSM()
	s := newTestServer(t, sm, CacheConfig{StageTTL: time.Minute, NegativeTTL: time.Minute}, false)
	req := &credprovider.FetchSecretRequest{Uri: uri(acct, "ate/team-a/throttled", "/stages/AWSCURRENT"), ActorSpiffeId: actorA}
	for range 3 {
		_, _ = s.FetchSecret(context.Background(), req)
	}
	if n := sm.calls.Load(); n != 3 {
		t.Fatalf("throttled answers were cached: %d calls, want 3", n)
	}
	req.Uri = uri(acct, "ate/team-a/nope", "/stages/AWSCURRENT")
	for range 3 {
		_, _ = s.FetchSecret(context.Background(), req)
	}
	if n := sm.calls.Load(); n != 4 {
		t.Fatalf("NotFound not negatively cached: %d calls, want 4", n)
	}
}

func TestCacheDoesNotBypassAuthz(t *testing.T) {
	sm := defaultSM()
	s := newTestServer(t, sm, CacheConfig{StageTTL: time.Minute}, false)
	u := uri(acct, "ate/team-a/github", "/stages/AWSCURRENT/keys/token")
	if _, err := s.FetchSecret(context.Background(), &credprovider.FetchSecretRequest{Uri: u, ActorSpiffeId: actorA}); err != nil {
		t.Fatal(err)
	}
	_, err := s.FetchSecret(context.Background(), &credprovider.FetchSecretRequest{Uri: u, ActorSpiffeId: actorB})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("team-b got %v from a warm cache, want PermissionDenied", err)
	}
}

func TestCacheScopedByAtespace(t *testing.T) {
	sm := defaultSM()
	getters := func(string, SecretRef) (SecretGetter, error) { return sm, nil }
	a, err := newAuthorizer(policyFile{Policies: []atespacePolicy{
		{Atespace: "team-a", AllowedSecrets: []secretGrant{{Account: acct, Region: "us-west-2", NamePrefix: "ate/"}}},
		{Atespace: "team-b", AllowedSecrets: []secretGrant{{Account: acct, Region: "us-west-2", NamePrefix: "ate/"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(getters, a, NewCache(CacheConfig{StageTTL: time.Minute}, time.Second), acct, true)
	u := uri(acct, "ate/team-a/github", "/stages/AWSCURRENT")
	for _, actor := range []string{actorA, actorB, actorA} {
		if _, err := s.FetchSecret(context.Background(), &credprovider.FetchSecretRequest{Uri: u, ActorSpiffeId: actor}); err != nil {
			t.Fatal(err)
		}
	}
	if n := sm.calls.Load(); n != 2 {
		t.Fatalf("atespace-scoped cache made %d calls, want 2 (one per atespace)", n)
	}
}

func TestFetchTimeoutIsDeadlineExceeded(t *testing.T) {
	sm := defaultSM()
	sm.delay = time.Second
	getters := func(string, SecretRef) (SecretGetter, error) { return sm, nil }
	s := NewServer(getters, testPolicy(t), NewCache(CacheConfig{}, 20*time.Millisecond), acct, false)
	_, err := s.FetchSecret(context.Background(), &credprovider.FetchSecretRequest{
		Uri: uri(acct, "ate/team-a/github", "/stages/AWSCURRENT"), ActorSpiffeId: actorA})
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("got %v, want DeadlineExceeded", err)
	}
}

func TestPolicyValidation(t *testing.T) {
	bad := []policyFile{
		{Policies: []atespacePolicy{{Atespace: ""}}},
		{Policies: []atespacePolicy{{Atespace: "a", AllowedSecrets: []secretGrant{{Account: "123", Region: "us-west-2", Name: "x"}}}}},
		{Policies: []atespacePolicy{{Atespace: "a", AllowedSecrets: []secretGrant{{Account: acct, Region: "us-west-2"}}}}},
		{Policies: []atespacePolicy{{Atespace: "a", AllowedSecrets: []secretGrant{{Account: acct, Region: "us-west-2", NamePrefix: "ate/team-a"}}}}},
		{Policies: []atespacePolicy{{Atespace: "Team_A", AllowedSecrets: []secretGrant{{Account: acct, Region: "us-west-2", NamePrefix: "ate/team-a/"}}}}},
		{Policies: []atespacePolicy{{Atespace: "a", AllowedSecrets: []secretGrant{{Account: acct, Region: "evil.example.com", Name: "x"}}}}},
	}
	for i, f := range bad {
		if _, err := newAuthorizer(f); err == nil {
			t.Errorf("policy %d accepted, want error", i)
		}
	}
	p := filepath.Join(t.TempDir(), "p.yaml")
	_ = os.WriteFile(p, []byte("policies:\n- atespace: a\n  allowedSecret: []\n"), 0o600)
	if _, err := LoadAuthorizer(p); err == nil {
		t.Error("misspelled field accepted, want strict error")
	}
	var nilAuthz *Authorizer
	if nilAuthz.Allowed("a", SecretRef{}) {
		t.Error("nil authorizer allowed a request")
	}
}

// TestServesPluginAPIOverGRPC drives the server through the generated
// substrate CredentialProvider client, as the egress gateway does.
func TestServesPluginAPIOverGRPC(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	credprovider.RegisterCredentialProviderServer(srv, newTestServer(t, defaultSM(), CacheConfig{StageTTL: time.Minute}, false))
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := credprovider.NewCredentialProviderClient(conn)
	resp, err := client.FetchSecret(context.Background(), &credprovider.FetchSecretRequest{
		Uri: uri(acct, "ate/team-a/github", "/stages/AWSCURRENT/keys/token"), ActorSpiffeId: actorA})
	if err != nil || string(resp.GetOpaqueBytes()) != "ghp_example" {
		t.Fatalf("FetchSecret over gRPC = %q, %v", resp.GetOpaqueBytes(), err)
	}
	_, err = client.FetchSecret(context.Background(), &credprovider.FetchSecretRequest{
		Uri: uri(acct, "ate/team-a/github", "/stages/AWSCURRENT"), ActorSpiffeId: actorB})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("team-b over gRPC: %v, want PermissionDenied", err)
	}
}

// captureLogs sends slog's default logger to a buffer for the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(orig) })
	return &buf
}

// The provider's logs name the actor and the secret on every outcome (served,
// refused by policy, failed upstream) and never carry a payload.
func TestLogsNameNotValue(t *testing.T) {
	logs := captureLogs(t)
	sm := defaultSM()
	s := newTestServer(t, sm, CacheConfig{StageTTL: time.Minute}, false)
	for _, req := range []*credprovider.FetchSecretRequest{
		{Uri: uri(acct, "ate/team-a/github", "/stages/AWSCURRENT/keys/token"), ActorSpiffeId: actorA},
		{Uri: uri(acct, "ate/team-a/raw", "/stages/AWSCURRENT"), ActorSpiffeId: actorA},
		{Uri: uri(acct, "ate/team-a/raw", "/stages/AWSCURRENT"), ActorSpiffeId: actorB},
		{Uri: uri(acct, "ate/team-a/denied", "/stages/AWSCURRENT"), ActorSpiffeId: actorA},
		{Uri: uri(acct, "ate/team-a/raw", "/stages/AWSCURRENT/keys/x"), ActorSpiffeId: actorA},
	} {
		_, _ = s.FetchSecret(context.Background(), req)
	}
	out := logs.String()
	for _, want := range []string{
		`"msg":"resolving credential"`,
		`"msg":"credential request denied: atespace not granted the secret"`,
		`"msg":"credential request failed"`,
		actorA, actorB,
		"arn:aws:secretsmanager:us-west-2:" + acct + ":secret:ate/team-a/raw",
		"arn:aws:secretsmanager:us-west-2:" + acct + ":secret:ate/team-a/denied",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("logs do not contain %q:\n%s", want, out)
		}
	}
	for _, secret := range []string{"ghp_example", "plain-token"} {
		if strings.Contains(out, secret) {
			t.Errorf("logs contain the secret value %q:\n%s", secret, out)
		}
	}
}

// The LRU drops the least recently used entry first, and an evicted secret is
// read again.
func TestCacheEvictsLeastRecentlyUsed(t *testing.T) {
	c := NewCache(CacheConfig{StageTTL: time.Minute, MaxEntries: 2}, time.Second)
	calls := map[string]int{}
	get := func(name string) {
		t.Helper()
		k := keyFor("", SecretRef{Account: acct, Region: "us-west-2", Name: name, Stage: "AWSCURRENT"})
		v, err := c.Get(context.Background(), "team-a", k, func(context.Context) ([]byte, error) {
			calls[name]++
			return []byte("v-" + name), nil
		})
		if err != nil || string(v) != "v-"+name {
			t.Fatalf("Get(%s) = %q, %v", name, v, err)
		}
	}
	get("a")
	get("b")
	get("a") // a is now the most recent
	get("c") // evicts b
	if n := c.Len(); n != 2 {
		t.Fatalf("Len = %d, want 2", n)
	}
	get("a")
	get("b")
	if calls["a"] != 1 || calls["b"] != 2 || calls["c"] != 1 {
		t.Fatalf("fetches = %v, want a:1 b:2 c:1", calls)
	}
}

func TestCacheBoundsPayloadBytes(t *testing.T) {
	c := NewCache(CacheConfig{StageTTL: time.Minute, MaxEntries: 10, MaxBytes: 5}, time.Second)
	calls := map[string]int{}
	get := func(name, value string) {
		t.Helper()
		k := keyFor("", SecretRef{Account: acct, Region: "us-west-2", Name: name, Stage: "AWSCURRENT"})
		got, err := c.Get(context.Background(), "team-a", k, func(context.Context) ([]byte, error) {
			calls[name]++
			return []byte(value), nil
		})
		if err != nil || string(got) != value {
			t.Fatalf("Get(%s) = %q, %v", name, got, err)
		}
	}

	get("a", "1234")
	get("b", "5678") // evicts a to stay under five bytes
	if got := c.Bytes(); got != 4 {
		t.Fatalf("Bytes = %d, want 4", got)
	}
	get("a", "1234")
	if calls["a"] != 2 {
		t.Fatalf("a fetched %d times, want 2 after byte eviction", calls["a"])
	}
	get("oversize", "123456")
	get("oversize", "123456")
	if calls["oversize"] != 2 {
		t.Fatalf("oversize value fetched %d times, want it never cached", calls["oversize"])
	}
	if got := c.Bytes(); got > 5 {
		t.Fatalf("Bytes = %d, exceeds configured maximum", got)
	}
}

func TestCacheWaitsForPerScopeSlotWithoutBlockingOtherAtespaces(t *testing.T) {
	c := NewCache(CacheConfig{
		MaxEntries:          10,
		MaxBytes:            1024,
		MaxInflight:         2,
		MaxInflightPerScope: 1,
	}, time.Second)
	entered := make(chan string, 3)
	releaseA := make(chan struct{})
	releaseB := make(chan struct{})
	start := func(scope, name string, release <-chan struct{}) <-chan error {
		result := make(chan error, 1)
		k := keyFor("", SecretRef{Account: acct, Region: "us-west-2", Name: name, Stage: "AWSCURRENT"})
		go func() {
			_, err := c.Get(context.Background(), scope, k, func(context.Context) ([]byte, error) {
				entered <- name
				if release != nil {
					<-release
				}
				return []byte("value"), nil
			})
			result <- err
		}()
		return result
	}

	firstA := start("team-a", "a1", releaseA)
	if got := <-entered; got != "a1" {
		t.Fatalf("first fetch = %q", got)
	}
	secondA := start("team-a", "a2", nil)
	select {
	case got := <-entered:
		t.Fatalf("same-scope fetch %q started before a slot was released", got)
	case <-time.After(25 * time.Millisecond):
	}

	teamB := start("team-b", "b", releaseB)
	if got := <-entered; got != "b" {
		t.Fatalf("other-scope fetch = %q, want b", got)
	}
	close(releaseB)
	if err := <-teamB; err != nil {
		t.Fatal(err)
	}

	close(releaseA)
	if err := <-firstA; err != nil {
		t.Fatal(err)
	}
	if got := <-entered; got != "a2" {
		t.Fatalf("waiting same-scope fetch = %q, want a2", got)
	}
	if err := <-secondA; err != nil {
		t.Fatal(err)
	}
}

func TestCacheAdmissionWaitIsBounded(t *testing.T) {
	c := NewCache(CacheConfig{MaxInflight: 1, MaxInflightPerScope: 1}, 25*time.Millisecond)
	release := make(chan struct{})
	entered := make(chan struct{})
	firstKey := keyFor("", SecretRef{Account: acct, Region: "us-west-2", Name: "a", Stage: "AWSCURRENT"})
	first := make(chan error, 1)
	go func() {
		_, err := c.Get(context.Background(), "team-a", firstKey, func(context.Context) ([]byte, error) {
			close(entered)
			<-release
			return []byte("value"), nil
		})
		first <- err
	}()
	<-entered

	secondKey := keyFor("", SecretRef{Account: acct, Region: "us-west-2", Name: "b", Stage: "AWSCURRENT"})
	start := time.Now()
	_, err := c.Get(context.Background(), "team-b", secondKey, func(context.Context) ([]byte, error) { return nil, nil })
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("admission wait = %v, want Unavailable", err)
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond || elapsed > time.Second {
		t.Fatalf("admission wait lasted %v, want about 25ms", elapsed)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

func TestAccessErrorDoesNotReturnAWSMessage(t *testing.T) {
	awsMessage := "User arn:aws:sts::111122223333:assumed-role/provider/session is not authorized"
	err := accessError(SecretRef{Account: acct, Region: "us-west-2", Name: "ate/team-a/x", Stage: "AWSCURRENT"},
		&smithy.GenericAPIError{Code: "AccessDeniedException", Message: awsMessage})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if strings.Contains(err.Error(), awsMessage) || strings.Contains(err.Error(), "assumed-role/provider/session") {
		t.Fatalf("gRPC error exposes the upstream AWS message: %v", err)
	}
}
