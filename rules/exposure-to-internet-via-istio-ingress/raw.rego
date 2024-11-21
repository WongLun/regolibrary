package armo_builtins
import future.keywords.in


deny[msga] {
    virtualservice := input[_]
    virtualservice.kind == "VirtualService"

    # Check if the VirtualService is connected to a Gateway
    gateway := input[_]
    gateway.kind == "Gateway"

    is_same_namespace(gateway, virtualservice)
    virtualservice.spec.gateways[_] == gateway.metadata.name

    # Find the connected Istio Ingress Gateway that should be a LoadBalancer if it is exposed to the internet
    istioingressgateway := input[_]
    istioingressgateway.kind == "Service"
    istioingressgateway.metadata.namespace == "istio-system"
    gateway.spec.selector[_] == istioingressgateway.metadata.labels[_]


    # Check if the Istio Ingress Gateway is exposed to the internet
    is_exposed_service(istioingressgateway)

    # Check if the VirtualService is connected to an workload
    # First, find the service that the VirtualService is connected to
    connected_service := input[_]
    connected_service.kind == "Service"
    fqsn := get_fqsn(get_namespace(virtualservice), virtualservice.spec.http[_].route[_].destination.host)
    target_ns := split(fqsn,".")[1]
    target_name := split(fqsn,".")[0]
    # Check if the service is in the same namespace as the VirtualService
    get_namespace(connected_service) == target_ns
    # Check if the service is the target of the VirtualService
    connected_service.metadata.name == target_name

    # Check if the service is connected to a workload
    wl := input[_]
    is_same_namespace(connected_service, wl)
    spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Pod", "Job", "CronJob"}
    spec_template_spec_patterns[wl.kind]
    wl_connected_to_service(wl, connected_service)

    result := svc_connected_to_virtualservice(connected_service, virtualservice)

    msga := {
        "alertMessage": sprintf("workload '%v' is exposed through virtualservice '%v'", [wl.metadata.name, virtualservice.metadata.name]),
        "packagename": "armo_builtins",
        "failedPaths": [],
        "fixPaths": [],
        "alertScore": 7,
        "alertObject": {
            "k8sApiObjects": [wl]
        },
        "relatedObjects": [
		{
	            "object": virtualservice,
		    "reviewPaths": result,
	            "failedPaths": result,
	        },
		{
	            "object": connected_service,
		}
        ]
    }
}

# ====================================================================================

get_namespace(obj) = namespace {
    obj.metadata
    obj.metadata.namespace
    namespace := obj.metadata.namespace
}

get_namespace(obj) = namespace {
    not obj.metadata.namespace
    namespace := "default"
}

is_same_namespace(obj1, obj2) {
    obj1.metadata.namespace == obj2.metadata.namespace
}

is_same_namespace(obj1, obj2) {
    not obj1.metadata.namespace
    obj2.metadata.namespace == "default"
}

is_same_namespace(obj1, obj2) {
    not obj2.metadata.namespace
    obj1.metadata.namespace == "default"
}

is_same_namespace(obj1, obj2) {
    not obj1.metadata.namespace
    not obj2.metadata.namespace
}

is_exposed_service(svc) {
    svc.spec.type == "NodePort"
}

is_exposed_service(svc) {
    svc.spec.type == "LoadBalancer"
}

wl_connected_to_service(wl, svc) {
    count({x | svc.spec.selector[x] == wl.metadata.labels[x]}) == count(svc.spec.selector)
}

wl_connected_to_service(wl, svc) {
    wl.spec.selector.matchLabels == svc.spec.selector
}

wl_connected_to_service(wl, svc) {
    count({x | svc.spec.selector[x] == wl.spec.template.metadata.labels[x]}) == count(svc.spec.selector)
}

svc_connected_to_virtualservice(svc, virtualservice) = result {
    host := virtualservice.spec.http[i].route[j].destination.host
    svc.metadata.name == host
    result := [sprintf("spec.http[%d].routes[%d].destination.host", [i,j])]
}

get_fqsn(ns, dest_host) = fqsn {
    # verify that this name is without the namespace
    count(split(".", dest_host)) == 1
    fqsn := sprintf("%v.%v.svc.cluster.local", [dest_host, ns])
}

get_fqsn(ns, dest_host) = fqsn {
    count(split(".", dest_host)) == 2
    fqsn := sprintf("%v.svc.cluster.local", [dest_host])
}

get_fqsn(ns, dest_host) = fqsn {
    count(split(".", dest_host)) == 4
    fqsn := dest_host
}


