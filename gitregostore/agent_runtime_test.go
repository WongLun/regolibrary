package gitregostore

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/resources"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// These fixtures must also work after the production processor filters inputs by
// rule metadata; passing data.json straight to OPA misses missing declarations.
func TestAgentRuntimeConfiguredInputs(t *testing.T) {
	for _, name := range []string{
		"agent-sandbox-hardened-runtime-class", "agent-runtime-image-registries",
		"agent-sandbox-strict-egress", "worker-pod-resource-ceilings",
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join("..", "rules", name)
			metadata, err := os.ReadFile(filepath.Join(root, "rule.metadata.json"))
			require.NoError(t, err)
			var rule reporthandling.PolicyRule
			require.NoError(t, json.Unmarshal(metadata, &rule))
			module, err := os.ReadFile(filepath.Join(root, "raw.rego"))
			require.NoError(t, err)
			cases, err := filepath.Glob(filepath.Join(root, "test", "*"))
			require.NoError(t, err)
			for _, path := range cases {
				t.Run(filepath.Base(path), func(t *testing.T) {
					var deps resources.RegoDependenciesData
					raw, err := os.ReadFile(filepath.Join(path, "data.json"))
					if !os.IsNotExist(err) {
						require.NoError(t, err)
						require.NoError(t, json.Unmarshal(raw, &deps))
					}
					filtered := resources.RegoDependenciesData{
						PostureControlInputs: deps.GetFilteredPostureControlConfigInputs(rule.ControlConfigInputs),
					}
					store, err := filtered.TOStorage()
					require.NoError(t, err)
					files, err := filepath.Glob(filepath.Join(path, "input", "*.yaml"))
					require.NoError(t, err)
					var input []interface{}
					for _, file := range files {
						contents, err := os.ReadFile(file)
						require.NoError(t, err)
						var object map[string]interface{}
						require.NoError(t, yaml.Unmarshal(contents, &object))
						input = append(input, object)
					}
					result, err := rego.New(rego.Query("data.armo_builtins.deny"),
						rego.Module(name, string(module)), rego.Input(input), rego.Store(store)).Eval(context.Background())
					require.NoError(t, err)
					require.Len(t, result, 1)
					actual := result[0].Expressions[0].Value.([]interface{})
					expectedFile, err := os.ReadFile(filepath.Join(path, "expected.json"))
					require.NoError(t, err)
					var expected []map[string]interface{}
					require.NoError(t, json.Unmarshal(expectedFile, &expected))
					require.Len(t, actual, len(expected))
					var gotPaths, wantPaths []string
					for _, finding := range actual {
						for _, p := range finding.(map[string]interface{})["failedPaths"].([]interface{}) {
							gotPaths = append(gotPaths, p.(string))
						}
					}
					for _, finding := range expected {
						for _, p := range finding["failedPaths"].([]interface{}) {
							wantPaths = append(wantPaths, p.(string))
						}
					}
					sort.Strings(gotPaths)
					sort.Strings(wantPaths)
					require.Equal(t, wantPaths, gotPaths)
				})
			}
		})
	}
}

// The standard rule runner merges repository defaults, so test an older
// configuration with no runtime allowlist directly through the filtered input
// path. This distinguishes an absent input from a configured default.
func TestAgentRuntimeMissingInputs(t *testing.T) {
	for _, name := range []string{"agent-sandbox-hardened-runtime-class", "agent-runtime-image-registries"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join("..", "rules", name)
			module, err := os.ReadFile(filepath.Join(root, "raw.rego"))
			require.NoError(t, err)
			metadata, err := os.ReadFile(filepath.Join(root, "rule.metadata.json"))
			require.NoError(t, err)
			var rule reporthandling.PolicyRule
			require.NoError(t, json.Unmarshal(metadata, &rule))
			deps := resources.RegoDependenciesData{PostureControlInputs: map[string][]string{}}
			filtered := resources.RegoDependenciesData{PostureControlInputs: deps.GetFilteredPostureControlConfigInputs(rule.ControlConfigInputs)}
			store, err := filtered.TOStorage()
			require.NoError(t, err)
			for _, kind := range []string{"Sandbox", "SandboxTemplate"} {
				var input interface{}
				require.NoError(t, json.Unmarshal([]byte(`[{"kind":"`+kind+`","metadata":{"name":"missing-config"},"spec":{"podTemplate":{"spec":{"runtimeClassName":"runc","containers":[{"image":"evil.example/actor"}]}}}}]`), &input))
				result, err := rego.New(rego.Query("data.armo_builtins.deny"), rego.Module(name, string(module)), rego.Input(input), rego.Store(store)).Eval(context.Background())
				require.NoError(t, err)
				require.Len(t, result, 1)
				require.Empty(t, result[0].Expressions[0].Value)
			}
		})
	}
}
