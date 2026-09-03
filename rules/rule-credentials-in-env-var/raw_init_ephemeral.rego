# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	sensitive_values := data.postureControlInputs.sensitiveValues
	pod := input[_]
	pod.kind == "Pod"
	value := sensitive_values[_]
	container := pod.spec.initContainers[i]
	env := container.env[j]
	regex.match(sprintf("(?i)%s", [value]), env.value)
	not is_allowed_value(env.value)
	not is_allowed_key_name(env.name)
	is_not_file_path(env.value)
	paths := [
		sprintf("spec.initContainers[%v].env[%v].name", [i, j]),
		sprintf("spec.initContainers[%v].env[%v].value", [i, j]),
	]
	msga := {
		"alertMessage": sprintf("Pod: %v has sensitive information in initContainer environment variables", [pod.metadata.name]),
		"alertScore": 9,
		"fixPaths": [],
		"deletePaths": paths,
		"failedPaths": paths,
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

deny contains msga if {
	sensitive_values := data.postureControlInputs.sensitiveValues
	pod := input[_]
	pod.kind == "Pod"
	value := sensitive_values[_]
	container := pod.spec.ephemeralContainers[i]
	env := container.env[j]
	regex.match(sprintf("(?i)%s", [value]), env.value)
	not is_allowed_value(env.value)
	not is_allowed_key_name(env.name)
	is_not_file_path(env.value)
	paths := [
		sprintf("spec.ephemeralContainers[%v].env[%v].name", [i, j]),
		sprintf("spec.ephemeralContainers[%v].env[%v].value", [i, j]),
	]
	msga := {
		"alertMessage": sprintf("Pod: %v has sensitive information in ephemeralContainer environment variables", [pod.metadata.name]),
		"alertScore": 9,
		"fixPaths": [],
		"deletePaths": paths,
		"failedPaths": paths,
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

deny contains msga if {
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	sensitive_values := data.postureControlInputs.sensitiveValues
	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	value := sensitive_values[_]
	container := wl.spec.template.spec.initContainers[i]
	env := container.env[j]
	regex.match(sprintf("(?i)%s", [value]), env.value)
	not is_allowed_value(env.value)
	not is_allowed_key_name(env.name)
	is_not_file_path(env.value)
	paths := [
		sprintf("spec.template.spec.initContainers[%v].env[%v].name", [i, j]),
		sprintf("spec.template.spec.initContainers[%v].env[%v].value", [i, j]),
	]
	msga := {
		"alertMessage": sprintf("%v: %v has sensitive information in initContainer environment variables", [wl.kind, wl.metadata.name]),
		"alertScore": 9,
		"fixPaths": [],
		"deletePaths": paths,
		"failedPaths": paths,
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

deny contains msga if {
	sensitive_values := data.postureControlInputs.sensitiveValues
	wl := input[_]
	wl.kind == "CronJob"
	value := sensitive_values[_]
	container := wl.spec.jobTemplate.spec.template.spec.initContainers[i]
	env := container.env[j]
	regex.match(sprintf("(?i)%s", [value]), env.value)
	not is_allowed_value(env.value)
	not is_allowed_key_name(env.name)
	is_not_file_path(env.value)
	paths := [
		sprintf("spec.jobTemplate.spec.template.spec.initContainers[%v].env[%v].name", [i, j]),
		sprintf("spec.jobTemplate.spec.template.spec.initContainers[%v].env[%v].value", [i, j]),
	]
	msga := {
		"alertMessage": sprintf("Cronjob: %v has sensitive information in initContainer environment variables", [wl.metadata.name]),
		"alertScore": 9,
		"fixPaths": [],
		"deletePaths": paths,
		"failedPaths": paths,
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [wl]},
	}
}
