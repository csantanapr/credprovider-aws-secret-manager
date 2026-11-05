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

// Command aws-sm-credential-provider serves substrate's CredentialProvider
// gRPC API from AWS Secrets Manager. The egress gateway calls it to resolve
// ate-secret://secretsmanager.amazonaws.com/... URIs for credential injection;
// it is the only component in that path with Secrets Manager access. It gets
// its AWS credentials from EKS Pod Identity.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"google.golang.org/grpc"

	"go.ate.dev/substrate/api/credprovider/v1"

	"plugins.go.ate.dev/credprovider-aws-secret-manager/internal/mtls"
	"plugins.go.ate.dev/credprovider-aws-secret-manager/internal/provider"
)

var (
	listenAddr   = flag.String("listen-address", ":50051", "gRPC listen address")
	healthAddr   = flag.String("health-address", ":9090", "HTTP listen address for /healthz and /readyz")
	serverBundle = flag.String("server-cred-bundle", "", "credential bundle (PKCS#8 key and certificate chain) presented for serving TLS (required)")
	clientCAFile = flag.String("client-ca-file", "", "trust bundle the caller's client certificate must chain to (required)")
	// No default: the gateway's namespace and ServiceAccount are known only to
	// the deployment.
	injectorIdentity = flag.String("injector-identity", "", "SPIFFE ID the caller's client certificate must carry: substrate's egress gateway, e.g. spiffe://<trust-domain>/ns/<namespace>/sa/atenet-egress (required)")
	policyFile       = flag.String("secret-policy-file", "", "path to the atespace→secrets authorization YAML (required)")
	awsRegion        = flag.String("region", "", "the provider's own AWS Region, for STS; empty uses AWS_REGION")
	atespaceRoleARN  = flag.String("atespace-role-arn", "", "optional IAM role assumed once per atespace with an ate-atespace session tag, so IAM also enforces atespace isolation")
	requirePodID     = flag.Bool("require-pod-identity", true, "exit unless EKS Pod Identity put credentials in the environment")
	logLevel         = flag.String("log-level", "info", "one of debug, info, warn, error")
	drainGrace       = flag.Duration("drain-grace", 5*time.Second, "how long to wait for in-flight RPCs on shutdown before a hard stop")
	// The egress gateway gives all of a request's injections 4s together.
	fetchTimeout = flag.Duration("fetch-timeout", 2*time.Second, "how long one GetSecretValue may take, retries included; keep it under the egress gateway's 4s injection budget")
	stageTTL     = flag.Duration("cache-ttl", 30*time.Second, "how long a stage reference (AWSCURRENT, ...) is served from memory; bounds the rotation lag; 0 disables caching")
	versionTTL   = flag.Duration("version-cache-ttl", time.Hour, "how long a version-ID reference, which never changes, is served from memory")
	negativeTTL  = flag.Duration("negative-cache-ttl", 5*time.Second, "how long a NotFound or PermissionDenied answer is reused")
	cacheEntries = flag.Int("cache-max-entries", 10000, "most secret versions held in memory (each at most 64 KiB)")
)

// version is set at build time with -ldflags "-X main.version=v0.1.0".
var version string

// roleARN matches an IAM role ARN and captures its account.
var roleARN = regexp.MustCompile(`^arn:aws[a-z-]*:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+$`)

func main() {
	flag.Parse()

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "invalid --log-level %q: %v\n", *logLevel, err)
		os.Exit(2)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	slog.Info("starting aws-sm-credential-provider", slog.String("version", buildVersion()))
	if err := run(context.Background()); err != nil {
		slog.Error("aws-sm-credential-provider exited with error", slog.Any("err", err))
		os.Exit(1)
	}
}

// checkFlags rejects a missing or malformed flag before anything is read.
func checkFlags() error {
	for _, f := range []struct{ name, value string }{
		{"--server-cred-bundle", *serverBundle},
		{"--client-ca-file", *clientCAFile},
		{"--injector-identity", *injectorIdentity},
		{"--secret-policy-file", *policyFile},
	} {
		if f.value == "" {
			return fmt.Errorf("%s is required", f.name)
		}
	}
	switch {
	case *fetchTimeout <= 0:
		return fmt.Errorf("--fetch-timeout must be positive, got %v", *fetchTimeout)
	case *stageTTL < 0 || *versionTTL < 0 || *negativeTTL < 0:
		return errors.New("--cache-ttl, --version-cache-ttl and --negative-cache-ttl must not be negative")
	case *cacheEntries <= 0:
		return fmt.Errorf("--cache-max-entries must be positive, got %d", *cacheEntries)
	case *awsRegion != "" && !provider.ValidRegion(*awsRegion):
		return fmt.Errorf("--region %q is not a region such as us-west-2", *awsRegion)
	case *atespaceRoleARN != "" && !roleARN.MatchString(*atespaceRoleARN):
		return fmt.Errorf("--atespace-role-arn %q is not an IAM role ARN", *atespaceRoleARN)
	}
	return nil
}

func run(ctx context.Context) error {
	if err := checkFlags(); err != nil {
		return err
	}
	authz, err := provider.LoadAuthorizer(*policyFile)
	if err != nil {
		return fmt.Errorf("secret policy: %w", err)
	}
	slog.Info("loaded secret authorization policy", slog.String("file", *policyFile), slog.Int("atespaces", authz.Atespaces()))

	// The Pod Identity webhook adds these only when a pod is created. A pod
	// that started before its association existed never gets them, so exit
	// and let it be restarted, rather than fall through to IMDS (blocked by a
	// hop limit of 1 on EKS nodes) and fail every request slowly.
	if *requirePodID && os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI") == "" {
		return errors.New("no EKS Pod Identity credentials in the environment: create the Pod Identity association for this ServiceAccount, then restart the pod (or pass --require-pod-identity=false to use other AWS credentials)")
	}

	creds, err := mtls.ServerCredentials(mtls.Config{
		ServerBundle:   *serverBundle,
		ClientCAFile:   *clientCAFile,
		CallerIdentity: *injectorIdentity,
	})
	if err != nil {
		return fmt.Errorf("server credentials: %w", err)
	}
	slog.Info("admitting callers", slog.String("client_ca", *clientCAFile), slog.String("required_san", *injectorIdentity))

	opts := []func(*config.LoadOptions) error{
		// Two attempts fit the fetch timeout. The gateway retries nothing
		// itself, but answers Unavailable with a retryable 503.
		config.WithRetryer(func() aws.Retryer { return retry.AddWithMaxAttempts(retry.NewStandard(), 2) }),
	}
	if *awsRegion != "" {
		opts = append(opts, config.WithRegion(*awsRegion))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("aws config: %w", err)
	}
	if !provider.ValidRegion(cfg.Region) {
		return fmt.Errorf("no AWS Region: set --region or AWS_REGION (got %q)", cfg.Region)
	}
	// Fail startup if no credentials resolve, and learn the home account.
	// GetCallerIdentity needs no grant.
	idCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	id, err := sts.NewFromConfig(cfg).GetCallerIdentity(idCtx, &sts.GetCallerIdentityInput{})
	cancel()
	if err != nil {
		return fmt.Errorf("resolving the provider's AWS identity: %w", err)
	}
	homeAccount := aws.ToString(id.Account)
	if m := roleARN.FindStringSubmatch(*atespaceRoleARN); m != nil {
		// The reader role's sessions read the secrets, so its account is the
		// one where a bare name resolves.
		homeAccount = m[1]
	}
	slog.Info("AWS identity", slog.String("arn", aws.ToString(id.Arn)), slog.String("region", cfg.Region),
		slog.String("home_account", homeAccount), slog.String("atespace_role", *atespaceRoleARN))

	pool := &clientPool{base: cfg, atespaceRoleARN: *atespaceRoleARN, sts: sts.NewFromConfig(cfg)}
	cache := provider.NewCache(provider.CacheConfig{StageTTL: *stageTTL, VersionTTL: *versionTTL,
		NegativeTTL: *negativeTTL, MaxEntries: *cacheEntries}, *fetchTimeout)
	slog.Info("cache", slog.Duration("stage_ttl", *stageTTL), slog.Duration("version_ttl", *versionTTL),
		slog.Duration("negative_ttl", *negativeTTL), slog.Int("max_entries", *cacheEntries))

	srv := grpc.NewServer(grpc.Creds(creds))
	credprovider.RegisterCredentialProviderServer(srv,
		provider.NewServer(pool.For, authz, cache, homeAccount, *atespaceRoleARN != ""))

	grpcLis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listenAddr, err)
	}
	healthLis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *healthAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *healthAddr, err)
	}
	var ready atomic.Bool
	healthSrv := &http.Server{Handler: healthHandler(&ready), ReadHeaderTimeout: 10 * time.Second}
	healthDone := make(chan error, 1)
	go func() { healthDone <- healthSrv.Serve(healthLis) }()

	shutdownCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownErr := make(chan error, 1)
	go func() {
		var err error
		select {
		case <-shutdownCtx.Done():
			slog.Info("shutting down")
		case err = <-healthDone:
			err = fmt.Errorf("health server: %w", err)
		}
		ready.Store(false)
		gracefulStop(srv, *drainGrace)
		_ = healthSrv.Close()
		shutdownErr <- err
	}()

	ready.Store(true)
	slog.Info("aws-sm-credential-provider listening", slog.String("address", grpcLis.Addr().String()), slog.String("health_address", healthLis.Addr().String()))
	// ErrServerStopped means shutdown began before Serve started: not a failure.
	if err := srv.Serve(grpcLis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serving: %w", err)
	}
	return <-shutdownErr
}

// gracefulStop lets in-flight RPCs finish for up to grace, then forces the
// server down.
func gracefulStop(srv *grpc.Server, grace time.Duration) {
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(grace):
		slog.Warn("graceful shutdown timed out; forcing stop", slog.Duration("grace", grace))
		srv.Stop()
	}
}

// healthHandler serves /healthz, which always succeeds so a draining pod is not
// restarted, and /readyz, which succeeds only while ready is set.
func healthHandler(ready *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// buildVersion returns the release or module version, else "dev", plus the VCS
// revision when the build recorded one.
func buildVersion() string {
	v := version
	info, ok := debug.ReadBuildInfo()
	if !ok {
		if v == "" {
			return "dev"
		}
		return v
	}
	if v == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		v = info.Main.Version
	}
	if v == "" {
		v = "dev"
	}
	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision == "" {
		return v
	}
	if modified == "true" {
		revision += "-dirty"
	}
	return v + " commit=" + revision
}
