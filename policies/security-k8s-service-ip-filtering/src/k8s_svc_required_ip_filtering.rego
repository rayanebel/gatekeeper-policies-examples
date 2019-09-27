package k8srequiredipfiltering

service_has_annotation_block {
    input.request.object.metadata.annotations
}

find_annotation(annotations, annotation) = res {
    annotations[annotation]
    res = annotations[annotation]
}

allow_no_ip_filtering_annotation_key = "security.k8s.io/allow-no-ip-filtering"

service_has_ip_filtering {
	input.request.object.spec.loadBalancerSourceRanges
    count(input.request.object.spec.loadBalancerSourceRanges) > 0
}

service_has_bypass_annotation {
  service_has_annotation_block
  find_annotation(input.request.object.metadata.annotations, allow_no_ip_filtering_annotation_key) == "true"
}

violation[{"msg": msg, "details": {}}] {
        input.request.kind.kind == "Service"
        input.request.object.spec.type == "LoadBalancer"
        not service_has_bypass_annotation
        not service_has_ip_filtering
        msg := sprintf("Rejecting service %v of type %v : 'spec.loadBalancerSourceRanges' properties must be set", [
        	input.request.object.metadata.name,
            input.request.object.spec.type])
}