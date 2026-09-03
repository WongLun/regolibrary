# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# input: network policies (NetworkPolicy, CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy)
# fails if no network policies are defined in a certain namespace

deny contains msga if {
	namespaces := [namespace | namespace = input[_]; namespace.kind == "Namespace"]
	namespace := namespaces[_]

	# Collect namespaces from all namespaced policies (NP + CNP)
	policy_names := [policy.metadata.namespace | policy = input[_]; is_network_policy_namespaced(policy)]

	# Fail if: no namespaced policy in this namespace AND no qualifying CCNPs exist
	not list_contains(policy_names, namespace.metadata.name)
	
	# Collect clusterwide policies that legitimately protect all namespaces
	qualifying_ccnps := [policy | policy = input[_]; is_ccnp_cluster_wide_coverage(policy)]
	count(qualifying_ccnps) == 0

	# Collect clusterwide policies scoped to exactly this namespace
	namespace_scoped_ccnps := [policy | policy = input[_]; is_ccnp_namespace_coverage(policy, namespace.metadata.name)]
	count(namespace_scoped_ccnps) == 0

	msga := {
		"alertMessage": sprintf("no policy is defined for namespace %v", [namespace.metadata.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [namespace]},
	}
}

is_network_policy_namespaced(policy) if {
	policy.kind == "NetworkPolicy"
}

is_network_policy_namespaced(policy) if {
	policy.kind == "CiliumNetworkPolicy"
}

# Returns the list of CiliumNetworkPolicySpec entries, unifying the
# `spec:` (single) and `specs:` (list) forms documented for CNP/CCNP CRDs.
# Either field may be present; both is also legal in Cilium.
cilium_policy_specs(policy) := specs if {
	from_spec := [s | s := policy.spec]
	from_specs := object.get(policy, "specs", [])
	specs := array.concat(from_spec, from_specs)
}

# A CCNP legitimately protects all namespaces only if at least one of its specs:
# 1. Selects all endpoints (empty endpointSelector or matchLabels: {})
# 2. Does not disable default-deny for both directions
# 3. Has at least ingress or egress rules defined
# (enableDefaultDeny, endpointSelector, ingress, egress are all per-CiliumNetworkPolicySpec.)

is_ccnp_cluster_wide_coverage(policy) if {
	policy.kind == "CiliumClusterwideNetworkPolicy"
	spec := cilium_policy_specs(policy)[_]
	ccnp_spec_selects_all_endpoints(spec)
	not ccnp_spec_default_deny_disabled(spec)
	ccnp_spec_has_ingress_or_egress(spec)
}

# Covers both `endpointSelector: {}` and `endpointSelector: { matchLabels: {} }`
# (and tolerates an empty `matchExpressions: []`).
ccnp_spec_selects_all_endpoints(spec) if {
	count(object.get(spec.endpointSelector, "matchLabels", {})) == 0
	count(object.get(spec.endpointSelector, "matchExpressions", [])) == 0
}

# A CCNP scoped to one namespace via Cilium's reserved identity label
# io.kubernetes.pod.namespace (plain or k8s:-prefixed, resolved from the pod's
# namespace, never present in pod.metadata.labels) protects that namespace,
# under the same conditions as cluster-wide coverage.
is_ccnp_namespace_coverage(policy, namespace_name) if {
	policy.kind == "CiliumClusterwideNetworkPolicy"
	spec := cilium_policy_specs(policy)[_]
	ccnp_spec_selects_namespace(spec, namespace_name)
	not ccnp_spec_default_deny_disabled(spec)
	ccnp_spec_has_ingress_or_egress(spec)
}

# matchLabels is conjunctive: every alias present must name the same namespace,
# and any further requirement narrows the policy to a subset of the namespace
# rather than covering it.
ccnp_spec_selects_namespace(spec, namespace_name) if {
	alias_keys := {"io.kubernetes.pod.namespace", "k8s:io.kubernetes.pod.namespace"}
	labels := object.get(spec.endpointSelector, "matchLabels", {})
	aliases := {value | some key in alias_keys; value := labels[key]}
	aliases == {namespace_name}
	every key, _ in labels {
		key in alias_keys
	}
	count(object.get(spec.endpointSelector, "matchExpressions", [])) == 0
}

# enableDefaultDeny explicitly disables both directions on this spec
ccnp_spec_default_deny_disabled(spec) if {
	spec.enableDefaultDeny.ingress == false
	spec.enableDefaultDeny.egress == false
}

ccnp_spec_has_ingress_or_egress(spec) if {
	spec.ingress
}

ccnp_spec_has_ingress_or_egress(spec) if {
	spec.egress
}

list_contains(list, element) if {
	some i
	list[i] == element
}
