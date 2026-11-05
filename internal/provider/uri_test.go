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

import "testing"

const base = "ate-secret://secretsmanager.amazonaws.com/accounts/111122223333/regions/us-west-2/secrets/"

func TestParseURI(t *testing.T) {
	good := []struct {
		uri  string
		want SecretRef
	}{
		{base + "github/stages/AWSCURRENT",
			SecretRef{Account: "111122223333", Region: "us-west-2", Name: "github", Stage: "AWSCURRENT"}},
		{base + "ate/team-a/github/stages/AWSCURRENT/keys/token",
			SecretRef{Account: "111122223333", Region: "us-west-2", Name: "ate/team-a/github", Stage: "AWSCURRENT", Key: "token"}},
		{base + "ate/team-a/github/versions/0d0a8f6e-1111-2222-3333-444455556666",
			SecretRef{Account: "111122223333", Region: "us-west-2", Name: "ate/team-a/github", VersionID: "0d0a8f6e-1111-2222-3333-444455556666"}},
		// Name segments that look like grammar words still parse from the right.
		{base + "a/stages/X/keys/k/stages/AWSCURRENT",
			SecretRef{Account: "111122223333", Region: "us-west-2", Name: "a/stages/X/keys/k", Stage: "AWSCURRENT"}},
		{base + "a/stages/stages/AWSPREVIOUS/keys/keys",
			SecretRef{Account: "111122223333", Region: "us-west-2", Name: "a/stages", Stage: "AWSPREVIOUS", Key: "keys"}},
		{base + "name+with=odd.chars@x-1/stages/custom_label",
			SecretRef{Account: "111122223333", Region: "us-west-2", Name: "name+with=odd.chars@x-1", Stage: "custom_label"}},
		{"ate-secret://secretsmanager.amazonaws.com/accounts/111122223333/regions/us-gov-west-1/secrets/x/stages/AWSCURRENT",
			SecretRef{Account: "111122223333", Region: "us-gov-west-1", Name: "x", Stage: "AWSCURRENT"}},
	}
	for _, tc := range good {
		got, err := ParseURI(tc.uri)
		if err != nil {
			t.Errorf("ParseURI(%q): %v", tc.uri, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseURI(%q) = %+v, want %+v", tc.uri, got, tc.want)
		}
	}

	bad := []string{
		base + "github",                      // no stage or version
		base + "github/stages",               // no stage value
		base + "github/keys/token",           // key without stage
		base + "github/stages/AWSCURRENT/",   // trailing slash
		base + "a//b/stages/AWSCURRENT",      // empty segment
		base + "../x/stages/AWSCURRENT",      // dot segment
		base + "a%2Fb/stages/AWSCURRENT",     // percent-encoding
		base + "a b/stages/AWSCURRENT",       // space
		base + "x/versions/not-a-uuid",       // version ID too short
		base + "x/stages/AWSCURRENT/keys/..", // dot key
		base + "x/stages/AWSCURRENT?y=1",     // query
		"ate-secret://secretsmanager.amazonaws.com/accounts/1111/regions/us-west-2/secrets/x/stages/AWSCURRENT",        // account
		"ate-secret://secretsmanager.amazonaws.com/accounts/111122223333/regions/evil.com/secrets/x/stages/AWSCURRENT", // region
		"ate-secret://k8s.io/default/ns/secret/key",                                                                    // other provider
		"https://secretsmanager.amazonaws.com/accounts/111122223333/x",                                                 // scheme
	}
	for _, uri := range bad {
		if ref, err := ParseURI(uri); err == nil {
			t.Errorf("ParseURI(%q) = %+v, want error", uri, ref)
		}
	}
}

func TestARNs(t *testing.T) {
	ref, err := ParseURI(base + "ate/team-a/github/stages/AWSCURRENT")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ref.PartialARN(), "arn:aws:secretsmanager:us-west-2:111122223333:secret:ate/team-a/github"; got != want {
		t.Errorf("PartialARN = %q, want %q", got, want)
	}
	cn := SecretRef{Account: "111122223333", Region: "cn-north-1", Name: "x"}
	if got := cn.Partition(); got != "aws-cn" {
		t.Errorf("Partition(cn-north-1) = %q", got)
	}
}
