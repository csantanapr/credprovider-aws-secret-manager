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
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// validCredentialURI is copied from substrate v1.0.0
// cmd/ateapi/internal/apivalidation/egress_policy.go, which plugins cannot
// import, with validation.IsDNS1123Subdomain replaced by an equivalent regexp
// and length check. It checks that the EgressPolicy API accepts every URI this
// provider serves.
var dns1123Subdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

func validCredentialURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "ate-secret" || u.Host == "" || u.Host != u.Hostname() || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(u.Host) > 253 || !dns1123Subdomain.MatchString(u.Host) {
		return false
	}
	escapedPath := u.EscapedPath()
	if escapedPath != u.Path {
		return false
	}
	if !strings.HasPrefix(escapedPath, "/") || strings.HasSuffix(escapedPath, "/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(escapedPath, "/"), "/")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
	}
	return true
}

var compatURIs = []string{
	base + "github/stages/AWSCURRENT",
	base + "ate/team-a/github/stages/AWSCURRENT/keys/token",
	base + "ate/team-a/github/versions/0d0a8f6e-1111-2222-3333-444455556666/keys/token",
	base + "name+with=odd.chars@x-1/stages/custom_label",
	base + "a/stages/X/keys/k/stages/AWSCURRENT",
}

func TestEgressPolicyAPIAcceptsProviderURIs(t *testing.T) {
	for _, u := range compatURIs {
		if _, err := ParseURI(u); err != nil {
			t.Errorf("provider refuses %q: %v", u, err)
		}
		if !validCredentialURI(u) {
			t.Errorf("EgressPolicy API would refuse %q", u)
		}
	}
}

// FuzzParseURI checks that every URI the provider accepts, the EgressPolicy
// API accepts too, and that a parsed ref names the secret the URI does.
func FuzzParseURI(f *testing.F) {
	for _, u := range compatURIs {
		f.Add(u)
	}
	f.Add(base + "a%2Fb/stages/AWSCURRENT")
	f.Add(base + "x/stages/AWSCURRENT/")
	f.Fuzz(func(t *testing.T, raw string) {
		ref, err := ParseURI(raw)
		if err != nil {
			return
		}
		if !validCredentialURI(raw) {
			t.Fatalf("provider accepts %q, which the EgressPolicy API refuses", raw)
		}
		if ref.Name == "" || (ref.Stage == "") == (ref.VersionID == "") {
			t.Fatalf("ParseURI(%q) = %+v: want a name and exactly one of stage and version", raw, ref)
		}
		if !strings.Contains(raw, "/secrets/"+ref.Name+"/") {
			t.Fatalf("ParseURI(%q) names secret %q, which the URI does not", raw, ref.Name)
		}
	})
}
