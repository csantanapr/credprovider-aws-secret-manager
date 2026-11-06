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

// Package provider implements substrate's CredentialProvider API over AWS
// Secrets Manager: it parses ate-secret:// URIs, authorizes the calling actor's
// atespace, and reads the secret through a cache.
package provider

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ProviderName is the ate-secret:// URI host this backend serves.
const ProviderName = "secretsmanager.amazonaws.com"

const uriScheme = "ate-secret"

// maxNameLen is Secrets Manager's limit on a secret name.
const maxNameLen = 512

var (
	accountID = regexp.MustCompile(`^[0-9]{12}$`)
	// region becomes part of the endpoint host the SDK dials, so it admits
	// only lower-case letters, digits and dashes in the shape of a region.
	region = regexp.MustCompile(`^[a-z]{2,4}(-[a-z]+)+-[0-9]+$`)
	// nameSegment is one '/'-separated part of a secret name. Secrets Manager
	// names allow letters, digits and /_+=.@-.
	nameSegment = regexp.MustCompile(`^[A-Za-z0-9_+=.@-]+$`)
	stageLabel  = regexp.MustCompile(`^[A-Za-z0-9_+=.@-]{1,256}$`)
	// A version ID is a 32-64 character client request token, usually a UUID.
	versionID       = regexp.MustCompile(`^[A-Za-z0-9-]{32,64}$`)
	arnRandomSuffix = regexp.MustCompile(`^[A-Za-z0-9]{6}$`)
)

// ValidRegion reports whether r has the shape of an AWS Region name, such as
// us-west-2. The provider dials Secrets Manager and STS endpoints built from
// it, so nothing else is accepted.
func ValidRegion(r string) bool { return region.MatchString(r) }

// SecretRef is a parsed URI:
//
//	ate-secret://secretsmanager.amazonaws.com/accounts/<account>/regions/<region>/secrets/<name...>/stages/<stage>[/keys/<key>]
//	ate-secret://secretsmanager.amazonaws.com/accounts/<account>/regions/<region>/secrets/<name...>/versions/<version-id>[/keys/<key>]
//
// <name...> may span several segments, as a hierarchical name like
// ate/team-a/github does. The tail is parsed from the right, so the encoding
// stays unambiguous even when a name segment is "stages" or "keys".
type SecretRef struct {
	Account   string
	Region    string
	Name      string
	Stage     string // exactly one of Stage and VersionID is set
	VersionID string
	Key       string // optional top-level JSON key
}

// Partition is the ARN partition of the ref's region.
func (r SecretRef) Partition() string { return PartitionOf(r.Region) }

// ARNPrefix is the start of every ARN this secret can have: Secrets Manager
// appends "-" and six random characters to the name.
func (r SecretRef) ARNPrefix() string {
	return fmt.Sprintf("arn:%s:secretsmanager:%s:%s:secret:%s-", r.Partition(), r.Region, r.Account, r.Name)
}

// MatchesSecretIdentity reports whether the service response names exactly
// this secret. Secrets Manager appends one six-character random suffix to the
// name in the ARN.
func (r SecretRef) MatchesSecretIdentity(name, arn string) bool {
	if name != r.Name || !strings.HasPrefix(arn, r.ARNPrefix()) {
		return false
	}
	return arnRandomSuffix.MatchString(strings.TrimPrefix(arn, r.ARNPrefix()))
}

// MatchesSecretVersion reports whether the response carries the version ID or
// staging label that the request selected.
func (r SecretRef) MatchesSecretVersion(versionID string, stages []string) bool {
	if r.VersionID != "" {
		return versionID == r.VersionID
	}
	for _, stage := range stages {
		if stage == r.Stage {
			return true
		}
	}
	return false
}

// PartialARN is the ARN without its random suffix, which Secrets Manager
// accepts as a SecretId and which a cross-account read requires.
func (r SecretRef) PartialARN() string {
	return strings.TrimSuffix(r.ARNPrefix(), "-")
}

// String names the secret version for logs and errors. It never holds a value.
func (r SecretRef) String() string {
	sel := "stage " + r.Stage
	if r.VersionID != "" {
		sel = "version " + r.VersionID
	}
	return fmt.Sprintf("%s (%s)", r.PartialARN(), sel)
}

// PartitionOf is the ARN partition of a region: aws, aws-cn, aws-us-gov or
// one of the isolated partitions.
func PartitionOf(region string) string {
	switch {
	case strings.HasPrefix(region, "eusc-"):
		return "aws-eusc"
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(region, "eu-isoe-"):
		return "aws-iso-e"
	case strings.HasPrefix(region, "us-isof-"):
		return "aws-iso-f"
	case strings.HasPrefix(region, "us-isob-"):
		return "aws-iso-b"
	case strings.HasPrefix(region, "us-iso-"):
		return "aws-iso"
	default:
		return "aws"
	}
}

// ParseURI parses a secretsmanager.amazonaws.com credential URI. Errors never
// echo the raw URI because malformed input can contain accidental credentials.
func ParseURI(raw string) (SecretRef, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return SecretRef{}, fmt.Errorf("credential URI cannot be parsed")
	}
	if u.Scheme != uriScheme {
		return SecretRef{}, fmt.Errorf("credential URI scheme must be %q", uriScheme)
	}
	if u.Host != ProviderName {
		return SecretRef{}, fmt.Errorf("credential URI names a provider this service does not serve")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return SecretRef{}, fmt.Errorf("credential URI must not contain user information, a query, or a fragment")
	}
	if u.EscapedPath() != u.Path {
		return SecretRef{}, fmt.Errorf("credential URI path must not contain percent-encoding")
	}
	const want = "accounts/<account>/regions/<region>/secrets/<name>/(stages/<stage>|versions/<id>)[/keys/<key>]"
	if !strings.HasPrefix(u.Path, "/") {
		return SecretRef{}, fmt.Errorf("credential URI path must have format %s", want)
	}
	seg := strings.Split(u.Path[1:], "/")
	for i, s := range seg {
		if s == "" {
			return SecretRef{}, fmt.Errorf("credential URI has an empty path segment at position %d", i)
		}
	}
	if len(seg) < 8 || seg[0] != "accounts" || seg[2] != "regions" || seg[4] != "secrets" {
		return SecretRef{}, fmt.Errorf("credential URI path must have format %s", want)
	}
	ref := SecretRef{Account: seg[1], Region: seg[3]}
	if !accountID.MatchString(ref.Account) {
		return SecretRef{}, fmt.Errorf("credential URI account must be a 12-digit account ID")
	}
	if !region.MatchString(ref.Region) {
		return SecretRef{}, fmt.Errorf("credential URI region must have a shape such as us-west-2")
	}

	rest := seg[5:]
	n := len(rest)
	var nameSegs []string
	var selKind, selVal string
	switch {
	case n >= 5 && rest[n-2] == "keys" && (rest[n-4] == "stages" || rest[n-4] == "versions"):
		nameSegs, selKind, selVal, ref.Key = rest[:n-4], rest[n-4], rest[n-3], rest[n-1]
	case n >= 3 && (rest[n-2] == "stages" || rest[n-2] == "versions"):
		nameSegs, selKind, selVal = rest[:n-2], rest[n-2], rest[n-1]
	default:
		return SecretRef{}, fmt.Errorf("credential URI requires a stage or version selector: want %s", want)
	}
	for _, s := range nameSegs {
		if s == "." || s == ".." || !nameSegment.MatchString(s) {
			return SecretRef{}, fmt.Errorf("credential URI secret name contains an invalid segment")
		}
	}
	ref.Name = strings.Join(nameSegs, "/")
	if len(ref.Name) > maxNameLen {
		return SecretRef{}, fmt.Errorf("credential URI secret name is longer than %d characters", maxNameLen)
	}
	switch selKind {
	case "stages":
		if !stageLabel.MatchString(selVal) {
			return SecretRef{}, fmt.Errorf("credential URI staging label is invalid")
		}
		ref.Stage = selVal
	case "versions":
		if !versionID.MatchString(selVal) {
			return SecretRef{}, fmt.Errorf("credential URI version ID is invalid")
		}
		ref.VersionID = selVal
	}
	if ref.Key == "." || ref.Key == ".." {
		return SecretRef{}, fmt.Errorf("credential URI key is invalid")
	}
	return ref, nil
}
