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
	"errors"
	"flag"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"go.ate.dev/substrate/api/credprovider/v1"
)

// /healthz passes regardless of readiness; /readyz follows the ready flag.
func TestHealthHandler(t *testing.T) {
	var ready atomic.Bool
	h := healthHandler(&ready)

	get := func(path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}

	if got := get("/healthz"); got != http.StatusOK {
		t.Errorf("/healthz before ready = %d, want 200", got)
	}
	if got := get("/readyz"); got != http.StatusServiceUnavailable {
		t.Errorf("/readyz before ready = %d, want 503", got)
	}

	ready.Store(true)
	if got := get("/readyz"); got != http.StatusOK {
		t.Errorf("/readyz when ready = %d, want 200", got)
	}

	ready.Store(false)
	if got := get("/readyz"); got != http.StatusServiceUnavailable {
		t.Errorf("/readyz while draining = %d, want 503", got)
	}
	if got := get("/healthz"); got != http.StatusOK {
		t.Errorf("/healthz while draining = %d, want 200", got)
	}
}

// setFlags sets command-line flags for one test and restores every flag after.
func setFlags(t *testing.T, values map[string]string) {
	t.Helper()
	orig := map[string]string{}
	flag.VisitAll(func(f *flag.Flag) { orig[f.Name] = f.Value.String() })
	t.Cleanup(func() {
		for name, v := range orig {
			_ = flag.Set(name, v)
		}
	})
	for name, v := range values {
		if err := flag.Set(name, v); err != nil {
			t.Fatalf("flag.Set(%s, %q): %v", name, v, err)
		}
	}
}

// run rejects a missing or malformed flag, an unreadable file, or a pod
// without Pod Identity credentials before it calls AWS or binds a port.
func TestRunRefusesBadConfiguration(t *testing.T) {
	const caller = "spiffe://cluster.local/ns/ate-system/sa/atenet-egress"
	policy := filepath.Join(t.TempDir(), "secret-policy.yaml")
	if err := os.WriteFile(policy, []byte("policies: []\n"), 0o600); err != nil {
		t.Fatalf("writing the policy: %v", err)
	}
	absent := filepath.Join(t.TempDir(), "absent")
	good := map[string]string{
		"server-cred-bundle": "/bundle.pem",
		"client-ca-file":     "/ca.pem",
		"injector-identity":  caller,
		"secret-policy-file": policy,
	}
	with := func(changes map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range good {
			m[k] = v
		}
		for k, v := range changes {
			m[k] = v
		}
		return m
	}
	const podID = "http://169.254.170.23/v1/credentials"
	tests := []struct {
		name  string
		flags map[string]string
		podID string
		// wantErr must be in the message; wantIs, if set, in the chain.
		wantErr string
		wantIs  error
	}{
		{name: "no server bundle", flags: with(map[string]string{"server-cred-bundle": ""}), wantErr: "--server-cred-bundle"},
		{name: "no client CA", flags: with(map[string]string{"client-ca-file": ""}), wantErr: "--client-ca-file"},
		{name: "no injector identity", flags: with(map[string]string{"injector-identity": ""}), wantErr: "--injector-identity"},
		{name: "no secret policy", flags: with(map[string]string{"secret-policy-file": ""}), wantErr: "--secret-policy-file"},
		{name: "fetch timeout not positive", flags: with(map[string]string{"fetch-timeout": "0s"}), wantErr: "--fetch-timeout"},
		{name: "negative cache TTL", flags: with(map[string]string{"negative-cache-ttl": "-1s"}), wantErr: "must not be negative"},
		{name: "no cache entries", flags: with(map[string]string{"cache-max-entries": "0"}), wantErr: "--cache-max-entries"},
		{name: "region not a region", flags: with(map[string]string{"region": "REPLACE_WITH_AWS_REGION"}), wantErr: "--region"},
		{name: "region an endpoint", flags: with(map[string]string{"region": "evil.example.com"}), wantErr: "--region"},
		{name: "role not an IAM role", flags: with(map[string]string{"atespace-role-arn": "arn:aws:iam::111122223333:user/x"}), wantErr: "--atespace-role-arn"},
		{name: "secret policy unreadable", flags: with(map[string]string{"secret-policy-file": absent}), podID: podID, wantErr: "secret policy", wantIs: fs.ErrNotExist},
		{name: "no Pod Identity credentials", flags: good, wantErr: "Pod Identity"},
		{name: "client CA unreadable", flags: with(map[string]string{"client-ca-file": absent}), podID: podID, wantErr: "server credentials", wantIs: fs.ErrNotExist},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setFlags(t, tc.flags)
			t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", tc.podID)

			err := run(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("run() error = %v, want one mentioning %q", err, tc.wantErr)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("run() error = %v, want one wrapping %v", err, tc.wantIs)
			}
		})
	}
}

// --require-pod-identity=false skips only the Pod Identity check.
func TestRunWithoutPodIdentityRequirement(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "secret-policy.yaml")
	if err := os.WriteFile(policy, []byte("policies: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setFlags(t, map[string]string{
		"server-cred-bundle":   "/bundle.pem",
		"client-ca-file":       filepath.Join(t.TempDir(), "absent"),
		"injector-identity":    "spiffe://cluster.local/ns/ate-system/sa/atenet-egress",
		"secret-policy-file":   policy,
		"require-pod-identity": "false",
	})
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "")
	if err := run(context.Background()); err == nil || !strings.Contains(err.Error(), "server credentials") {
		t.Fatalf("run() error = %v, want it to get past the Pod Identity check to the server credentials", err)
	}
}

func TestRoleARN(t *testing.T) {
	for arn, account := range map[string]string{
		"arn:aws:iam::111122223333:role/ate-secrets-reader":           "111122223333",
		"arn:aws-us-gov:iam::111122223333:role/path/to/reader":        "111122223333",
		"arn:aws-cn:iam::444455556666:role/ate+reader=x,y.z@w_v-u":    "444455556666",
		"arn:aws:iam::111122223333:user/someone":                      "",
		"arn:aws:sts::111122223333:assumed-role/ate-secrets-reader/x": "",
		"arn:aws:iam::1111:role/x":                                    "",
	} {
		m := roleARN.FindStringSubmatch(arn)
		got := ""
		if m != nil {
			got = m[1]
		}
		if got != account {
			t.Errorf("roleARN account of %q = %q, want %q", arn, got, account)
		}
	}
}

func TestBuildVersionPrefersExplicitVersion(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })

	version = "v9.9.9"
	if got := buildVersion(); !strings.HasPrefix(got, "v9.9.9") {
		t.Errorf("buildVersion() = %q, want it to start with v9.9.9", got)
	}
	version = ""
	if got := buildVersion(); got == "" {
		t.Error("buildVersion() is empty without an explicit version")
	}
}

// blockingProvider blocks FetchSecret until release is closed or the call is
// canceled, closing entered once the call starts.
type blockingProvider struct {
	credprovider.UnimplementedCredentialProviderServer
	entered chan struct{}
	release chan struct{}
}

func (p *blockingProvider) FetchSecret(ctx context.Context, _ *credprovider.FetchSecretRequest) (*credprovider.FetchSecretResponse, error) {
	close(p.entered)
	select {
	case <-p.release:
		return &credprovider.FetchSecretResponse{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// startBlockingServer serves p in memory and starts one FetchSecret against it,
// returning the server and the call's result.
func startBlockingServer(t *testing.T, p *blockingProvider) (*grpc.Server, <-chan error) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	credprovider.RegisterCredentialProviderServer(srv, p)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	result := make(chan error, 1)
	go func() {
		_, err := credprovider.NewCredentialProviderClient(conn).FetchSecret(context.Background(), &credprovider.FetchSecretRequest{})
		result <- err
	}()
	select {
	case <-p.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("FetchSecret never reached the server")
	}
	return srv, result
}

// gracefulStop returns once an in-flight call completes within the grace period.
func TestGracefulStopDrains(t *testing.T) {
	p := &blockingProvider{entered: make(chan struct{}), release: make(chan struct{})}
	srv, result := startBlockingServer(t, p)

	stopped := make(chan struct{})
	go func() {
		gracefulStop(srv, time.Minute)
		close(stopped)
	}()
	close(p.release)
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("gracefulStop did not return after the in-flight call finished")
	}
	if err := <-result; err != nil {
		t.Errorf("in-flight FetchSecret = %v, want it to complete", err)
	}
}

// gracefulStop cuts off a call still running when the grace period ends.
func TestGracefulStopForcesAfterGrace(t *testing.T) {
	const grace = 100 * time.Millisecond
	p := &blockingProvider{entered: make(chan struct{}), release: make(chan struct{})}
	srv, result := startBlockingServer(t, p)

	start := time.Now()
	gracefulStop(srv, grace)
	if elapsed := time.Since(start); elapsed < grace || elapsed > 50*grace {
		t.Errorf("gracefulStop returned after %v, want about %v", elapsed, grace)
	}
	if err := <-result; err == nil {
		t.Error("in-flight FetchSecret succeeded, want it cut off")
	}
}
