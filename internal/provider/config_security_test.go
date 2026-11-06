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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type iamPolicy struct {
	Statement []struct {
		Action    any            `json:"Action"`
		Condition map[string]any `json:"Condition"`
		Resource  string         `json:"Resource"`
	} `json:"Statement"`
}

func readIAMPolicy(t *testing.T, name string) iamPolicy {
	t.Helper()
	path := filepath.Join("..", "..", "config", "iam", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var policy iamPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(policy.Statement) != 1 {
		t.Fatalf("%s has %d statements, want 1", path, len(policy.Statement))
	}
	return policy
}

func conditionMap(t *testing.T, condition map[string]any, operator string) map[string]any {
	t.Helper()
	value, ok := condition[operator].(map[string]any)
	if !ok {
		t.Fatalf("condition %q = %#v, want an object", operator, condition[operator])
	}
	return value
}

func TestPodIdentityTrustIsBoundToWorkload(t *testing.T) {
	statement := readIAMPolicy(t, "pod-identity-trust-policy.json").Statement[0]
	equals := conditionMap(t, statement.Condition, "StringEquals")
	for key, want := range map[string]string{
		"aws:SourceAccount":                         "REPLACE_WITH_AWS_ACCOUNT_ID",
		"aws:RequestTag/kubernetes-namespace":       "ate-system",
		"aws:RequestTag/kubernetes-service-account": "aws-sm-credential-provider",
	} {
		if got := equals[key]; got != want {
			t.Errorf("%s = %#v, want %q", key, got, want)
		}
	}
}

func TestPerAtespaceRolePoliciesAreTagAndKMSBound(t *testing.T) {
	for _, name := range []string{"provider-role-assume-reader-policy.json", "atespace-reader-trust-policy.json"} {
		condition := readIAMPolicy(t, name).Statement[0].Condition
		if got := conditionMap(t, condition, "Null")["aws:RequestTag/ate-atespace"]; got != "false" {
			t.Errorf("%s permits a missing atespace tag: %#v", name, got)
		}
	}
	trust := readIAMPolicy(t, "atespace-reader-trust-policy.json").Statement[0]
	if got := conditionMap(t, trust.Condition, "StringLike")["aws:RequestTag/ate-atespace"]; got != "?*" {
		t.Errorf("reader trust atespace request tag = %#v, want a nonempty value", got)
	}

	kms := readIAMPolicy(t, "atespace-reader-kms-policy.json").Statement[0]
	if got := conditionMap(t, kms.Condition, "StringEquals")["kms:ViaService"]; got != "secretsmanager.REPLACE_WITH_AWS_REGION.REPLACE_WITH_AWS_DNS_SUFFIX" {
		t.Errorf("reader KMS ViaService = %#v", got)
	}
	wantContext := "arn:REPLACE_WITH_AWS_PARTITION:secretsmanager:REPLACE_WITH_AWS_REGION:REPLACE_WITH_AWS_ACCOUNT_ID:secret:ate/${aws:PrincipalTag/ate-atespace}/*"
	if got := conditionMap(t, kms.Condition, "StringLike")["kms:EncryptionContext:SecretARN"]; got != wantContext {
		t.Errorf("reader KMS encryption context = %#v, want %q", got, wantContext)
	}
}

func TestDirectRoleKMSIsSecretContextBound(t *testing.T) {
	statement := readIAMPolicy(t, "provider-role-kms-policy.json").Statement[0]
	want := "arn:REPLACE_WITH_AWS_PARTITION:secretsmanager:REPLACE_WITH_AWS_REGION:REPLACE_WITH_AWS_ACCOUNT_ID:secret:ate/*"
	if got := conditionMap(t, statement.Condition, "StringLike")["kms:EncryptionContext:SecretARN"]; got != want {
		t.Fatalf("direct-role KMS encryption context = %#v, want %q", got, want)
	}
}

func TestDeploymentDisablesKubernetesAPITokenAndBoundsResources(t *testing.T) {
	path := filepath.Join("..", "..", "config", "deployment.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{
		"automountServiceAccountToken: false",
		"--cache-max-bytes=67108864",
		"--fetch-concurrency=64",
		"--atespace-fetch-concurrency=8",
		"--rpc-concurrency=128",
		"--grpc-connection-limit=16",
		"--max-connection-age=5m",
		"--expected-role-arn=arn:REPLACE_WITH_AWS_PARTITION:iam::REPLACE_WITH_AWS_ACCOUNT_ID:role/aws-sm-credential-provider",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("deployment is missing %q", required)
		}
	}
}

func TestAllIAMTemplatesAreValidJSON(t *testing.T) {
	dir := filepath.Join("..", "..", "config", "iam")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			Statement []map[string]any `json:"Statement"`
		}
		if err := json.Unmarshal(data, &document); err != nil {
			t.Errorf("%s is not valid JSON: %v", entry.Name(), err)
			continue
		}
		if len(document.Statement) == 0 {
			t.Errorf("%s has no statements", entry.Name())
		}
		if strings.Contains(string(data), "arn:aws:") {
			t.Errorf("%s hardcodes the commercial AWS partition", entry.Name())
		}
		if strings.Contains(entry.Name(), "cross-account") {
			if len(document.Statement) != 2 || !strings.Contains(string(data), "REPLACE_WITH_REMOTE_AWS_ACCOUNT_ID") {
				t.Errorf("%s does not include explicit remote secret and KMS permissions", entry.Name())
			}
			if strings.HasPrefix(entry.Name(), "atespace-reader-") && !strings.Contains(string(data), "${aws:PrincipalTag/ate-atespace}") {
				t.Errorf("%s does not bind remote access to the atespace principal tag", entry.Name())
			}
		}
		if strings.Contains(entry.Name(), "kms-policy") && !strings.Contains(string(data), "REPLACE_WITH_KMS_KEY_ID") {
			t.Errorf("%s does not mark the KMS key ID for replacement", entry.Name())
		}
	}
}
