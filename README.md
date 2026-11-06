# aws-secret-manager credential provider

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A [substrate](https://github.com/agent-substrate/substrate) credential provider
backed by AWS Secrets Manager. It implements substrate's `CredentialProvider`
gRPC API (`api/credprovider/v1`) for egress credential injection: given an
`ate-secret://secretsmanager.amazonaws.com/...` URI, it reads the secret from
Secrets Manager and returns its value to substrate's egress gateway, which puts
it into the actor's outbound request. The secret stays in Secrets Manager, and
the actor never holds it.

It runs on Amazon EKS and gets its AWS credentials from EKS Pod Identity.

## Endpoint

The manifests in `config/` deploy the provider into substrate's `ate-system`
namespace:

| | |
|---|---|
| Provider name | `secretsmanager.amazonaws.com`, the host of its `ate-secret://` credential URIs |
| Address | `aws-sm-credential-provider.ate-system.svc:50051` |
| API | `substrate.credprovider.v1.CredentialProvider/FetchSecret` over mutual TLS |

The provider's serving certificate names the Service's DNS name, so callers
must use exactly this address.

## Credential URIs

The URI names an account, a Region, a secret and either a staging label or a
version ID, optionally followed by a key into the secret's JSON value:

```
ate-secret://secretsmanager.amazonaws.com/accounts/<account>/regions/<region>/secrets/<name>/stages/<stage>[/keys/<key>]
ate-secret://secretsmanager.amazonaws.com/accounts/<account>/regions/<region>/secrets/<name>/versions/<version-id>[/keys/<key>]
```

- `<account>` is the 12-digit ID of the account that holds the secret.
- `<region>` is the secret's Region, such as `us-west-2`. The provider reads
  the secret from that Region's endpoint. The URI host stays
  `secretsmanager.amazonaws.com`: it names the provider, not the endpoint.
- `<name>` is the secret's name, and may span several segments, as a
  hierarchical name such as `ate/team-a/github` does. Each segment is letters,
  digits or `_+=.@-`, other than `.` and `..`. Write the name, not the ARN.
- A stage or a version is required: `stages/AWSCURRENT` follows rotations,
  `stages/AWSPREVIOUS` or a custom label names another stage, and
  `versions/<version-id>` pins one version. A URI with neither is refused
  rather than read as `AWSCURRENT`.
- `<key>` names a top-level key of a value holding a JSON object, such as
  `{"token": "..."}`. It is a single path segment other than `.` or `..`.

The tail is read from the right, so a name segment called `stages` or `keys`
stays unambiguous. User information, queries, fragments, percent-encoding and
empty path segments (a doubled or trailing slash) are refused. Every URI the
provider accepts also passes substrate's EgressPolicy validation.

For example, with an EgressPolicy rule:

```yaml
rules:
- https:
    hostnames: ["api.example.com"]
    effects:
      replaceHeaders:
      - header: Authorization
        prefix: "Bearer "
        credentialUri: ate-secret://secretsmanager.amazonaws.com/accounts/111122223333/regions/us-west-2/secrets/ate/team-a/github/stages/AWSCURRENT
```

## Responses

Without a key, `FetchSecret` returns `SecretBinary` verbatim, or the bytes of
`SecretString`. With a key, it returns the key's value, which must be a JSON
string, with its JSON escapes decoded. So a key can select `password` from an
RDS secret, but not the numeric `port`.

The egress gateway trims trailing CR and LF from the value and refuses an
empty value or one containing any other control character, since the value
becomes part of an HTTP header. A multi-line credential, such as a PEM-encoded
key, cannot be injected.

The gateway gives all of a request's injections 4 seconds together. Each read
may take up to `--fetch-timeout`, 2s by default, two attempts included.

The gateway answers `Unavailable` and `DeadlineExceeded` with a retryable 503
and every other code with a 403:

| Condition | Code |
|---|---|
| The URI is malformed, lacks a stage or version, or names another provider | `InvalidArgument` |
| The actor's atespace is not granted the secret, or the actor identity is unusable | `PermissionDenied` |
| IAM refuses the read (`AccessDeniedException`), KMS cannot decrypt it (`DecryptionFailure`), or the secret resolved to another ARN | `PermissionDenied` |
| The secret, stage or version does not exist or has no value, or the JSON object has no such key | `NotFound` |
| The secret is scheduled for deletion (`InvalidRequestException`), or with a key, the value is not a JSON object or the key's value is not a string | `FailedPrecondition` |
| Secrets Manager rejects a parameter | `InvalidArgument` |
| Secrets Manager does not answer in time | `DeadlineExceeded` |
| Throttling, an outage, no credentials from the Pod Identity agent, or a read-concurrency limit | `Unavailable` |

Error messages and logs name the secret, the key and the AWS error code, but
never contain the value.

## Caching and rotation

Secrets Manager bills each `GetSecretValue` call, and its quota for the call
(10,000 per second per account and Region) is shared with every other workload
in the account. The gateway does not cache credentials, so without a cache
every injected request would be one read. The provider keeps an in-memory LRU
per replica:

- A stage reference is served from memory for `--cache-ttl`, 30s by default.
  A version ID never changes, so it is kept for `--version-cache-ttl`, 1h.
- `NotFound`, `PermissionDenied` and similar answers are kept for
  `--negative-cache-ttl`, 5s, so a misconfigured policy cannot use up the
  quota. Throttling and outages are never cached: the next request reads again.
- Concurrent reads of one secret share one call. Distinct reads are bounded
  globally and per atespace; reaching either limit returns `Unavailable` so
  the gateway emits a retryable 503.
- Cache payloads are bounded by both `--cache-max-entries` and
  `--cache-max-bytes`; a single value larger than the byte budget is returned
  but not cached.
- Authorization runs on every request, before the cache: a value one atespace
  read is never served to another atespace without the grant.

**Rotation lag.** After `AWSCURRENT` moves to a new version, each replica can
inject the old value for up to `--cache-ttl`. Use a rotation strategy that
keeps the previous credential valid for longer than that, such as alternating
users, or lower the TTL. `--cache-ttl=0` disables stage-value caching;
version and negative entries use their own TTL flags.

With 100 hot secrets on 2 replicas and a 30s TTL, the provider makes about
576,000 calls a day, whatever the request rate.

## Security model

- **Only the egress gateway may call.** The provider serves mutual TLS with a
  certificate from substrate's servicedns signer, and admits a caller only if
  its certificate chains to substrate's podidentity trust bundle and carries
  the egress gateway's SPIFFE ID, `--injector-identity`. The NetworkPolicy in
  `config/` also admits only the gateway's pods on port 50051.
- **Each atespace resolves only the secrets its policy grants.** The provider
  takes the atespace from the actor SPIFFE ID the gateway sends and, before
  the cache and before AWS, refuses with `PermissionDenied` a URI that no grant
  for that atespace covers. The policy is default-deny.
- **IAM bounds the rest.** The provider's role may read only secrets under
  `ate/` that carry the tag `ate.dev/injectable=true`
  ([`config/iam/provider-role-policy.json`](config/iam/provider-role-policy.json)),
  so the secrets other workloads use stay out of its reach even if the policy
  grants too much. Anyone who may tag secrets can make one injectable, so
  limit `secretsmanager:TagResource` on that key.
- **Optional: IAM per atespace.** With `--atespace-role-arn`, IAM also
  enforces atespace isolation, and CloudTrail names the atespace (see
  [Per-atespace IAM](#per-atespace-iam)).
- **The actor never holds the secret.** It sends a placeholder; the gateway
  replaces it on the way out. Its environment, files and snapshots never
  contain the value.

CloudTrail logs each `GetSecretValue` as the provider's role session. The
provider logs which actor asked for which secret, so per-actor audit comes
from its logs.

## Install on Amazon EKS

Prerequisites:

- An EKS cluster with the EKS Pod Identity Agent add-on, running substrate
  v1.0.0-rc.3 or newer. The provider gets its serving certificate and its
  callers' trust bundle from substrate's pod certificate controller.
- For the NetworkPolicy to take effect, the Amazon VPC CNI with
  `enableNetworkPolicy: "true"`.
- An image: `make image` builds one with docker (or `make deploy` builds and
  pushes it with [ko](https://ko.build) to `KO_DOCKER_REPO`). Push it to a
  registry the nodes can pull from, such as Amazon ECR.

**1. Create the provider's IAM role and Pod Identity association.** The role
trusts EKS Pod Identity only for the named cluster, the `ate-system` namespace,
and the `aws-sm-credential-provider` ServiceAccount
([`config/iam/pod-identity-trust-policy.json`](config/iam/pod-identity-trust-policy.json))
and may read injectable secrets under `ate/`
([`config/iam/provider-role-policy.json`](config/iam/provider-role-policy.json)).
Replace every `REPLACE_WITH_...` value in the IAM templates: account,
Region, cluster name, KMS key ID, ARN partition (`aws`, `aws-us-gov`,
`aws-cn`, ...), and DNS suffix (`amazonaws.com` or the partition's suffix).
Then:

```bash
aws iam create-role --role-name aws-sm-credential-provider \
  --assume-role-policy-document file://config/iam/pod-identity-trust-policy.json
aws iam put-role-policy --role-name aws-sm-credential-provider --policy-name read-injectable-secrets \
  --policy-document file://config/iam/provider-role-policy.json
aws eks create-pod-identity-association --cluster-name <cluster> \
  --namespace ate-system --service-account aws-sm-credential-provider \
  --role-arn arn:<partition>:iam::<account>:role/aws-sm-credential-provider
```

For secrets encrypted with a customer managed KMS key, also add
[`config/iam/provider-role-kms-policy.json`](config/iam/provider-role-kms-policy.json),
and allow the role in the key policy. Secrets under the AWS managed key
`aws/secretsmanager` need no KMS permission.

The association must exist before the provider's pods are created: EKS adds
the Pod Identity endpoint and token projection only when a pod is created. A
pod that started without them exits at startup; restart the Deployment once
the association exists. In required mode the provider constructs the Pod
Identity credential provider directly. Both its local credential request and
all STS and Secrets Manager requests use proxy-free, no-redirect HTTP clients.
Required mode ignores default shared files and refuses conflicting static,
web-identity, profile, relative-container, custom-CA, or configured-endpoint
settings. The one CA bundle it accepts is the image's own system bundle,
which the distroless base sets in `SSL_CERT_FILE`. EKS Pod Identity sets
`AWS_REGION` and `AWS_DEFAULT_REGION` on the pod; the required `--region`
flag overrides them, so they cannot select the STS Region.

**2. Store a secret.** Name it under `ate/<atespace>/` and tag it injectable.
Pass the value from a file, not on the command line, where other users can read
it:

```bash
aws secretsmanager create-secret --name ate/team-a/github \
  --secret-string file://token.txt --tags Key=ate.dev/injectable,Value=true
```

Its URI is
`ate-secret://secretsmanager.amazonaws.com/accounts/<account>/regions/<region>/secrets/ate/team-a/github/stages/AWSCURRENT`.

To keep several credentials in one secret, store a JSON object and name the
key: `.../stages/AWSCURRENT/keys/token`.

**3. Apply the secret policy.** Edit
[`config/secret-policy.yaml`](config/secret-policy.yaml), the
`aws-sm-credential-provider-secret-policy` ConfigMap, to list the secrets each
atespace may resolve, then apply it. The provider's pods mount it, so it must
exist first. `make deploy` leaves it out, so a redeploy never overwrites it.

```bash
kubectl apply -f config/secret-policy.yaml
```

The policy format:

```yaml
policies:
- atespace: team-a
  allowedSecrets:
  - account: "111122223333"      # quoted: a 12-digit account ID
    region: us-west-2
    namePrefix: ate/team-a/      # every secret under ate/team-a/; must end in /
  - account: "444455556666"
    region: eu-west-1
    name: shared/github          # exactly this secret
```

Each grant sets exactly one of `name` and `namePrefix`. The file is parsed
strictly, so a misspelled field stops the provider at startup. The provider
reads the policy once, at startup; after editing it, restart the provider:

```bash
kubectl -n ate-system rollout restart deployment/aws-sm-credential-provider
```

**4. Deploy the provider.** Set `--region` and replace the partition and
account in `--expected-role-arn` in
[`config/deployment.yaml`](config/deployment.yaml), then from this repository:

```bash
KO_DOCKER_REPO=<registry> make deploy
kubectl -n ate-system rollout status deployment/aws-sm-credential-provider
```

With an image built by `make image`, render the manifests with
`kubectl kustomize config`, replace the `ko://` image with yours, and apply
them. The Deployment runs two replicas, with a PodDisruptionBudget that keeps
one serving, and a NetworkPolicy that admits only the egress gateway.

**5. Point the egress gateway at the provider.** The gateway serves several
providers, one per URI host. Keep the bundled Kubernetes Secrets provider and
add this one, from a substrate checkout:

```bash
go run ./cmd/ate-setup deploy atenet --credential-provider='[{"name":"k8s.io"},{"name":"secretsmanager.amazonaws.com","address":"aws-sm-credential-provider.ate-system.svc:50051"}]'
```

Pass the same value on every later `deploy ate-system` or `deploy atenet`, or
set it as `ATE_CREDENTIAL_PROVIDER`: each install sets the gateway's provider
list from it. Deploy the provider first: until it serves, every injection that
names it fails closed with 503, and a gateway that started before the provider
can take a couple of minutes to reconnect.

**6. Give actors the trust bundle and a rule.** Actors whose EgressPolicy has
`https` rules need substrate's egress trust bundle (substrate's
`docs/guides/egress-trust-bundle.md`). Then add a `replaceHeaders` effect as
under [Credential URIs](#credential-uris), and have the actor send the header
with any placeholder value.

**Uninstall.** Point the gateway back at the bundled provider first: removing
the provider while the gateway still names it makes every fetch for its URIs
fail.

```bash
go run ./cmd/ate-setup deploy atenet --credential-provider='{"name":"k8s.io"}'   # from a substrate checkout
make undeploy                                                                      # from this repository
```

`make undeploy` removes the ServiceAccount, Deployment, Service,
NetworkPolicy and PodDisruptionBudget, and leaves the secret policy in place.

## Network

- **Ingress.** Only `app: atenet-egress` pods on 50051, from
  [`config/networkpolicy.yaml`](config/networkpolicy.yaml). Kubelet probes
  use port 9090.
- **Egress.** The provider calls the Pod Identity agent (169.254.170.23:80),
  STS, and Secrets Manager in each Region its URIs name, over HTTPS. Substrate
  sets no egress policy on `ate-system`; if you add one, allow these. Interface
  VPC endpoints for `secretsmanager` and `sts` keep the traffic off the
  internet.
- **No IMDS in the deployment.** With the default
  `--require-pod-identity=true`, the provider uses only the EKS Pod Identity
  endpoint and never enters the SDK's IMDS credential chain. The explicit
  development override `--require-pod-identity=false` restores the SDK's
  default chain. EKS nodes should still enforce IMDSv2 with a hop limit of 1.

## Per-atespace IAM

By default the provider's one role reads every injectable secret, and the
secret policy keeps atespaces apart. With `--atespace-role-arn`, IAM keeps
them apart too: the provider assumes a reader role once per atespace, with the
session tag `ate-atespace=<atespace>` and the atespace as the session name,
and the reader role may read only `ate/${aws:PrincipalTag/ate-atespace}/*`.
CloudTrail then shows the atespace of every read.

| File | Attach to |
|---|---|
| [`config/iam/provider-role-assume-reader-policy.json`](config/iam/provider-role-assume-reader-policy.json) | The provider's role: may assume and tag the reader role |
| [`config/iam/atespace-reader-trust-policy.json`](config/iam/atespace-reader-trust-policy.json) | The reader role's trust policy: only the provider's role, only with an `ate-atespace` tag |
| [`config/iam/atespace-reader-policy.json`](config/iam/atespace-reader-policy.json) | The reader role's Secrets Manager permissions |
| [`config/iam/atespace-reader-kms-policy.json`](config/iam/atespace-reader-kms-policy.json) | The reader role's KMS permission for a customer managed key; also allow the reader role in the key policy |

These are alternative permission sets. In per-atespace mode, do **not** attach
`provider-role-policy.json` or `provider-role-kms-policy.json` to the base
provider role. The base role gets only
`provider-role-assume-reader-policy.json`; the reader role gets the two reader
policies. This prevents a base-role client from bypassing per-atespace IAM.

In this mode, cache entries are kept per atespace, so IAM decides each
atespace's first read itself. Chained role sessions last at most one hour; the
provider starts refreshing them up to five minutes before expiration and
bounds the complete `AssumeRole` operation, including retries, to five seconds.
This layer guards against a mistake in the secret policy, not against a
compromised provider, which holds the role that may assume any atespace's tag.

## Cross-account secrets

A remote secret needs permission on both sides. Cross-account access requires
a customer managed KMS key because the AWS managed `aws/secretsmanager` key
cannot grant a principal in another account access. The remote account's
secret resource policy must trust the provider or reader role, and that role's
own identity policy must explicitly name the remote secret ARN. The remote key
policy and the role's identity policy must also allow `kms:Decrypt` for that
key.

Use the policy matching the selected mode:

| File | Attach to |
|---|---|
| [`config/iam/provider-role-cross-account-policy.json`](config/iam/provider-role-cross-account-policy.json) | The provider role in direct-read mode |
| [`config/iam/atespace-reader-cross-account-policy.json`](config/iam/atespace-reader-cross-account-policy.json) | The reader role in per-atespace mode; never the base provider role |

Replace every remote partition, Region, account, secret-prefix or
secret-root, KMS-key, and DNS-suffix placeholder. Narrow each direct-mode
statement to the exact remote prefix that the secret policy grants. In
per-atespace mode, `REPLACE_WITH_REMOTE_SECRET_ROOT` must end in `/`; remote
secrets then live under `<root>/<atespace>/`, so both `GetSecretValue` and the
KMS encryption context remain bound to `${aws:PrincipalTag/ate-atespace}`.
These identity policies supplement, rather than replace, the remote secret
resource policy and KMS key policy.

## Flags

| Flag | Default | Purpose |
|---|---|---|
| `--listen-address` | `:50051` | gRPC listen address |
| `--health-address` | `:9090` | HTTP address for `/healthz` and `/readyz` |
| `--server-cred-bundle` | required | Serving credential bundle: PKCS#8 key and certificate chain |
| `--client-ca-file` | required | Trust bundle the caller's certificate must chain to |
| `--injector-identity` | required | SPIFFE ID of substrate's egress gateway, the only caller the provider accepts; `spiffe://cluster.local/ns/ate-system/sa/atenet-egress` in a default install |
| `--secret-policy-file` | required | Atespace→secrets policy YAML |
| `--region` | required with Pod Identity | The provider's own Region for STS; secrets are read in the Region their URI names |
| `--atespace-role-arn` | none | Reader role assumed per atespace ([Per-atespace IAM](#per-atespace-iam)) |
| `--expected-role-arn` | none | IAM role ARN the startup STS identity must match; the supplied deployment sets it |
| `--require-pod-identity` | `true` | Use only the EKS Pod Identity endpoint and token file; `false` deliberately restores the SDK's default credential chain for development |
| `--fetch-timeout` | `2s` | Time limit for one read, two attempts included; keep it under the gateway's 4s injection budget |
| `--cache-ttl` | `30s` | How long a stage reference is served from memory; `0` disables stage-value caching |
| `--version-cache-ttl` | `1h` | How long a version-ID reference is served from memory |
| `--negative-cache-ttl` | `5s` | How long a `NotFound` or `PermissionDenied` answer is reused |
| `--cache-max-entries` | `10000` | Most secret versions held in memory per replica; the byte limit can evict sooner |
| `--cache-max-bytes` | `67108864` | Maximum retained secret payload bytes per replica (64 MiB) |
| `--fetch-concurrency` | `64` | Maximum distinct concurrent Secrets Manager reads per replica |
| `--atespace-fetch-concurrency` | `8` | Maximum distinct concurrent reads attributed to one atespace |
| `--rpc-concurrency` | `128` | Maximum concurrent `FetchSecret` handlers across all client connections |
| `--grpc-connection-limit` | `16` | Maximum accepted gRPC connections; per-connection streams divide the RPC allowance across this bound |
| `--max-connection-age` | `5m` | Nominal gRPC connection age; gRPC applies up to 10% jitter before the client reconnects and presents a current certificate |
| `--max-connection-age-grace` | `30s` | Grace period before closing a connection that reached its maximum age |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error` |
| `--drain-grace` | `5s` | How long in-flight calls may finish on shutdown |

At startup the provider checks the flags, loads the policy, constructs the
explicit Pod Identity credential source, validates its certificate and trust
bundle, and calls `sts:GetCallerIdentity` (which needs no permission) to fail
fast without credentials, verify `--expected-role-arn` when set, and learn its
own account. A secret in that account is read by name; a secret in another
account is read by its ARN. Cross-account reads require the local identity
policy, remote secret resource policy, and, for a customer managed key, both
the local KMS permission and remote key policy described above.

## Limits

- Values the gateway injects are single-line: no PEM keys.
- A key selects only a string value at the top level of a JSON object.
- `BatchGetSecretValue` is not used, and AWS's
  `aws-secretsmanager-caching-go` library is not either: it serves a stale
  value when a refresh fails, and this provider fails closed instead.
- To disable every cache class, set `--cache-ttl=0`,
  `--version-cache-ttl=0`, and `--negative-cache-ttl=0`. Setting only
  `--cache-ttl=0` disables stage-value caching.
- The policy is read once, at startup: a change needs a restart.
  Certificates reload when they rotate; readiness strictly parses the serving
  chain and client trust bundle, checks every certificate's validity, and
  fails on a missing or invalid Pod Identity token. Each readiness probe also
  retrieves through the SDK credential cache, so expiration or a transient
  refresh error triggers a bounded retry without waiting for application
  traffic. Authenticated gRPC connections are recycled after
  `--max-connection-age` so rotations apply to existing clients.
- No metrics endpoint yet.

## Development

```bash
make test               # go test -race ./...
make verify             # gofmt, go vet, go mod tidy check
make fmt                # gofmt -w .
make image              # docker build, IMAGE=aws-sm-credential-provider:dev
make release-manifest   # manifests with the image pinned by digest
make release-images     # VERSION=<tag> KO_DOCKER_REPO=<repo>: push the release image
```

Two packages are copies of substrate code kept in step by hand, since only
substrate's public `api/` and `pkg/` packages can be imported:
`internal/credbundle` of substrate's `internal/credbundle`, and `internal/mtls`
of the server credentials in `cmd/credential-provider/kubernetes-secrets`.
The actor SPIFFE ID parser in `internal/provider/authz.go` and the URI check
in `internal/provider/apicompat_test.go` are copies too.
