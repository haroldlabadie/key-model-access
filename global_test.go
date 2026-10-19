package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestGlobalDenyPrecedenceAndResolvedIdentity(t *testing.T) {
	for _, policies := range [][]policyConfig{nil, {{CallerScope: scopeA}}, {{CallerScope: scopeA, AllowModels: []string{"*"}}}} {
		installTestPolicy(t, policyDocument{Version: 3, GlobalDenyModels: []string{"blocked", "private-*"}, Policies: policies})
		for _, scope := range []string{"", scopeA, scopeB} {
			for _, method := range []string{methodRequestInterceptBefore, methodRequestInterceptAfter} {
				for _, pair := range [][2]string{{"blocked", "blocked"}, {"warmup-codex-account/blocked", "blocked"}, {"public-alias", "private-model"}, {"public-alias(high)", "blocked(high)"}, {"blocked(8192)", "blocked(8192)"}, {"BLOCKED", "different"}} {
					raw, _ := json.Marshal(requestInterceptRequest{RequestedModel: pair[0], Model: pair[1], Metadata: map[string]any{"caller_scope": scope}})
					result, err := handleMethod(method, raw)
					if err != nil {
						t.Fatal(err)
					}
					var response requestInterceptResponse
					unwrapEnvelope(t, result, &response)
					if !response.Terminate || response.StatusCode != http.StatusForbidden || !strings.Contains(string(response.ResponseBody), `"reason":"global_deny"`) {
						t.Fatalf("global deny bypass: %s %#v", method, response)
					}
				}
			}
		}
	}
}

func TestGlobalDoesNotStripArbitraryVendorPrefix(t *testing.T) {
	snapshot, _, err := compileDocument(policyDocument{Version: 3, GlobalDenyModels: []string{"blocked"}})
	if err != nil {
		t.Fatal(err)
	}
	if globalDeniedRule(snapshot, "vendor/blocked", "vendor/blocked") != "" {
		t.Fatal("arbitrary prefix stripped")
	}
	if globalDeniedRule(snapshot, "ok", "ok") != "" {
		t.Fatal("normal model denied")
	}
}

func TestGlobalPolicyRoundTripWithoutKeys(t *testing.T) {
	for _, ext := range []string{".toml", ".yaml", ".json"} {
		path := filepath.Join(t.TempDir(), "policy"+ext)
		doc := policyDocument{Version: 3, GlobalDenyModels: []string{"blocked"}, Policies: []policyConfig{}}
		if err := writePolicyFile(path, doc); err != nil {
			t.Fatal(err)
		}
		got, err := readPolicyFile(path)
		if err != nil {
			t.Fatal(err)
		}
		snap, _, err := compileDocument(got)
		if err != nil {
			t.Fatal(err)
		}
		if globalDeniedRule(snap, "blocked") == "" || len(snap.ByCallerScope) != 0 {
			t.Fatal("global-only policy lost")
		}
	}
}

func TestGlobalLegacySaveCannotEraseRules(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 3, GlobalDenyModels: []string{"blocked"}})
	for _, body := range []string{`{"version":2,"policies":[]}`, `{"version":3,"policies":[]}`} {
		raw, err := managementReplacePolicies([]byte(body), etagForRevision(globalState.policyRevision()))
		if err != nil {
			t.Fatal(err)
		}
		var response managementResponse
		unwrapEnvelope(t, raw, &response)
		if response.StatusCode < 400 {
			t.Fatal("old client erased global rules")
		}
		_, snap, _, _, _, _ := globalState.current()
		if globalDeniedRule(snap, "blocked") == "" {
			t.Fatal("rule lost")
		}
	}
	raw, err := managementReplacePolicies([]byte(`{"version":3,"global_deny_models":[],"policies":[]}`), etagForRevision(globalState.policyRevision()))
	if err != nil {
		t.Fatal(err)
	}
	var response managementResponse
	unwrapEnvelope(t, raw, &response)
	if response.StatusCode != 200 {
		t.Fatalf("explicit clear failed: %s", response.Body)
	}
}
