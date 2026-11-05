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
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.ate.dev/substrate/api/credprovider/v1"
)

// SecretGetter is the subset of *secretsmanager.Client the server uses.
type SecretGetter interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// Getters returns the client for a ref. Production wiring keys it by region
// (one client per region); with per-atespace role chaining it is also keyed by
// atespace, each with credentials from sts:AssumeRole tagged with it.
type Getters func(atespace string, ref SecretRef) (SecretGetter, error)

// Server implements credprovider.CredentialProviderServer.
type Server struct {
	credprovider.UnimplementedCredentialProviderServer

	getters Getters
	authz   *Authorizer
	cache   *Cache
	// homeAccount is the account the reading credentials belong to. A secret
	// there is read by name; any other account needs the (partial) ARN.
	homeAccount string
	// scopeCacheByAtespace keys the cache by atespace, for per-atespace IAM.
	scopeCacheByAtespace bool
}

// NewServer serves FetchSecret: authz decides first, then cache answers or
// calls getters' client.
func NewServer(getters Getters, authz *Authorizer, cache *Cache, homeAccount string, scopeCacheByAtespace bool) *Server {
	return &Server{getters: getters, authz: authz, cache: cache, homeAccount: homeAccount, scopeCacheByAtespace: scopeCacheByAtespace}
}

// FetchSecret resolves a URI to the secret payload or to one key's string value.
func (s *Server) FetchSecret(ctx context.Context, req *credprovider.FetchSecretRequest) (*credprovider.FetchSecretResponse, error) {
	ref, err := ParseURI(req.GetUri())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	atespace, err := actorAtespace(req.GetActorSpiffeId())
	if err != nil {
		slog.WarnContext(ctx, "credential request denied: unusable actor identity", slog.Any("err", err))
		return nil, status.Errorf(codes.PermissionDenied, "actor identity is required and must be a valid actor SPIFFE URI: %v", err)
	}
	// Authorize before the cache: a cached payload is never a bypass.
	if !s.authz.Allowed(atespace, ref) {
		slog.WarnContext(ctx, "credential request denied: atespace not granted the secret",
			slog.String("atespace", atespace), slog.String("secret", ref.String()), slog.String("actor", req.GetActorSpiffeId()))
		return nil, status.Errorf(codes.PermissionDenied, "atespace %q is not permitted to resolve %s", atespace, ref)
	}
	slog.InfoContext(ctx, "resolving credential", slog.String("provider", ProviderName),
		slog.String("secret", ref.String()), slog.String("key", ref.Key), slog.String("actor", req.GetActorSpiffeId()))

	scope := ""
	if s.scopeCacheByAtespace {
		scope = atespace
	}
	payload, err := s.cache.Get(ctx, keyFor(scope, ref), func(fctx context.Context) ([]byte, error) {
		return s.read(fctx, atespace, ref)
	})
	if err == nil && ref.Key != "" {
		payload, err = keyValue(ref, payload)
	}
	if err != nil {
		// Errors name the secret and the AWS error code, never the payload.
		slog.WarnContext(ctx, "credential request failed", slog.String("code", status.Code(err).String()),
			slog.String("secret", ref.String()), slog.String("key", ref.Key), slog.String("actor", req.GetActorSpiffeId()),
			slog.Any("err", err))
		return nil, err
	}
	return &credprovider.FetchSecretResponse{OpaqueBytes: payload}, nil
}

// read calls GetSecretValue and checks the answer names the secret asked for.
func (s *Server) read(ctx context.Context, atespace string, ref SecretRef) ([]byte, error) {
	client, err := s.getters(atespace, ref)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%s: no Secrets Manager client: %v", ref, err)
	}
	in := &secretsmanager.GetSecretValueInput{SecretId: aws.String(ref.Name)}
	if ref.Account != s.homeAccount {
		in.SecretId = aws.String(ref.PartialARN())
	}
	if ref.VersionID != "" {
		in.VersionId = aws.String(ref.VersionID)
	} else {
		in.VersionStage = aws.String(ref.Stage)
	}
	out, err := client.GetSecretValue(ctx, in)
	if err != nil {
		return nil, accessError(ref, err)
	}
	// A name ending in -XXXXXX can be taken for a full ARN; refuse anything
	// but the account, region and name the URI names.
	if !strings.HasPrefix(aws.ToString(out.ARN), ref.ARNPrefix()) {
		return nil, status.Errorf(codes.PermissionDenied, "%s resolved to a different secret", ref)
	}
	switch {
	case out.SecretBinary != nil:
		if len(out.SecretBinary) == 0 {
			return nil, status.Errorf(codes.NotFound, "%s has an empty payload", ref)
		}
		return out.SecretBinary, nil
	case aws.ToString(out.SecretString) != "":
		return []byte(aws.ToString(out.SecretString)), nil
	default:
		return nil, status.Errorf(codes.NotFound, "%s has no payload", ref)
	}
}

// accessError maps a Secrets Manager error to a code the gateway acts on:
// Unavailable/DeadlineExceeded -> retryable 503, anything else -> 403.
func accessError(ref SecretRef, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Errorf(codes.DeadlineExceeded, "%s: Secrets Manager did not answer in time", ref)
	}
	var ae smithy.APIError
	if !errors.As(err, &ae) {
		// Credential retrieval (Pod Identity agent), DNS, TLS: transient.
		return status.Errorf(codes.Unavailable, "%s: %v", ref, err)
	}
	msg := ae.ErrorCode() + ": " + ae.ErrorMessage()
	switch ae.ErrorCode() {
	case "ResourceNotFoundException":
		return status.Errorf(codes.NotFound, "%s not found", ref)
	case "AccessDeniedException", "UnrecognizedClientException", "InvalidSignatureException",
		// STS's code, when the per-atespace reader role refuses the provider.
		"AccessDenied":
		return status.Errorf(codes.PermissionDenied, "not permitted to read %s: %s", ref, msg)
	case "DecryptionFailure":
		// No kms:Decrypt on the secret's key, or the key is disabled.
		return status.Errorf(codes.PermissionDenied, "cannot decrypt %s: %s", ref, msg)
	case "InvalidRequestException":
		// For example a secret scheduled for deletion.
		return status.Errorf(codes.FailedPrecondition, "reading %s: %s", ref, msg)
	case "InvalidParameterException", "ValidationException":
		return status.Errorf(codes.InvalidArgument, "reading %s: %s", ref, msg)
	default:
		// ThrottlingException, InternalServiceError, unknown: retryable.
		return status.Errorf(codes.Unavailable, "reading %s: %s", ref, msg)
	}
}

// keyValue returns one string value from a JSON object payload.
func keyValue(ref SecretRef, data []byte) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%s: payload is not a JSON object", ref)
	}
	raw, ok := obj[ref.Key]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "%s: payload has no key %q", ref, ref.Key)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%s: value of key %q is not a JSON string", ref, ref.Key)
	}
	str, ok := v.(string)
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "%s: value of key %q is not a JSON string", ref, ref.Key)
	}
	return []byte(str), nil
}
