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
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"sigs.k8s.io/yaml"
)

// policyFile is the atespace -> secrets policy, mounted from a ConfigMap.
//
//	policies:
//	- atespace: team-a
//	  allowedSecrets:
//	  - account: "111122223333"
//	    region: us-west-2
//	    namePrefix: ate/team-a/
type policyFile struct {
	Policies []atespacePolicy `json:"policies"`
}

type atespacePolicy struct {
	Atespace       string        `json:"atespace"`
	AllowedSecrets []secretGrant `json:"allowedSecrets"`
}

// secretGrant admits one secret (name) or every secret under a hierarchy
// (namePrefix, which must end in "/" so ate/team-a/ never admits ate/team-ab).
type secretGrant struct {
	Account    string `json:"account"`
	Region     string `json:"region"`
	Name       string `json:"name,omitempty"`
	NamePrefix string `json:"namePrefix,omitempty"`
}

func (g secretGrant) admits(ref SecretRef) bool {
	if g.Account != ref.Account || g.Region != ref.Region {
		return false
	}
	if g.Name != "" {
		return g.Name == ref.Name
	}
	return strings.HasPrefix(ref.Name, g.NamePrefix)
}

// Authorizer is default-deny; a nil Authorizer refuses everything.
type Authorizer struct {
	grants map[string][]secretGrant
}

// LoadAuthorizer reads the policy YAML strictly, so a typo fails startup.
func LoadAuthorizer(path string) (*Authorizer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading secret policy file %q: %w", path, err)
	}
	var file policyFile
	if err := yaml.UnmarshalStrict(data, &file); err != nil {
		return nil, fmt.Errorf("parsing secret policy file %q: %w", path, err)
	}
	return newAuthorizer(file)
}

func newAuthorizer(file policyFile) (*Authorizer, error) {
	grants := map[string][]secretGrant{}
	for i, p := range file.Policies {
		if p.Atespace == "" {
			return nil, fmt.Errorf("secret policy %d: atespace is required", i)
		}
		if !dns1123Label.MatchString(p.Atespace) {
			return nil, fmt.Errorf("secret policy %d: atespace %q is not a valid atespace name", i, p.Atespace)
		}
		for j, g := range p.AllowedSecrets {
			switch {
			case !accountID.MatchString(g.Account):
				return nil, fmt.Errorf("secret policy %d grant %d: account %q must be a 12-digit account ID (quote it in YAML)", i, j, g.Account)
			case !region.MatchString(g.Region):
				return nil, fmt.Errorf("secret policy %d grant %d: region %q is not a region", i, j, g.Region)
			case (g.Name == "") == (g.NamePrefix == ""):
				return nil, fmt.Errorf("secret policy %d grant %d: set exactly one of name and namePrefix", i, j)
			case g.NamePrefix != "" && !strings.HasSuffix(g.NamePrefix, "/"):
				return nil, fmt.Errorf("secret policy %d grant %d: namePrefix %q must end in /", i, j, g.NamePrefix)
			}
			grants[p.Atespace] = append(grants[p.Atespace], g)
		}
	}
	return &Authorizer{grants: grants}, nil
}

// Allowed reports whether atespace may resolve ref.
func (a *Authorizer) Allowed(atespace string, ref SecretRef) bool {
	if a == nil {
		return false
	}
	for _, g := range a.grants[atespace] {
		if g.admits(ref) {
			return true
		}
	}
	return false
}

// Atespaces is the number of atespaces the policy grants anything to, for the
// startup log.
func (a *Authorizer) Atespaces() int {
	if a == nil {
		return 0
	}
	return len(a.grants)
}

// The rest of this file is a copy of substrate's
// internal/resources.ActorRefFromActorSPIFFEID, which plugins cannot import.

// actorTrustDomain is the trust domain of the actor SPIFFE IDs substrate mints.
const actorTrustDomain = "substrate-actor.local"

// dns1123Label matches a substrate resource name, atespaces included.
var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// actorAtespace returns the atespace of an actor SPIFFE ID,
// spiffe://substrate-actor.local/actor/<atespace>/<name>. It follows substrate's
// internal/resources.ActorRefFromActorSPIFFEID, which this module cannot import.
func actorAtespace(id string) (string, error) {
	const format = "spiffe://" + actorTrustDomain + "/actor/<atespace>/<name>"
	u, err := url.Parse(id)
	if err != nil {
		return "", fmt.Errorf("invalid actor SPIFFE ID %q: %w", id, err)
	}
	if u.Scheme != "spiffe" || u.Host != actorTrustDomain || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%q does not have format %s", id, format)
	}
	segments := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(segments) != 3 || segments[0] != "actor" {
		return "", fmt.Errorf("%q does not have format %s", id, format)
	}
	atespace, name := segments[1], segments[2]
	if !dns1123Label.MatchString(atespace) {
		return "", fmt.Errorf("%q is not a valid atespace", atespace)
	}
	if !dns1123Label.MatchString(name) {
		return "", fmt.Errorf("%q is not a valid actor name", name)
	}
	return atespace, nil
}
