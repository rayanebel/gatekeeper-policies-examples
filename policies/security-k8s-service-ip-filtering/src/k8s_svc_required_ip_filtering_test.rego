package k8srequiredipfiltering_test

import data.k8srequiredipfiltering

test_deny_service_without_ip_filtering_properties {
    payload := {
        "kind": "AdmissionReview",
        "request": {
            "kind": {
                "kind": "Service",
                "version": "v1"
            },
            "object": {
                "metadata": {
                    "name": "nginx",
                    "creationTimestamp": null,
                    "labels": {
                        "run": "nginx"
                    }
                },
                "spec": {
                    "ports": [
                        {
                            "protocol": "TCP",
                            "port": 80,
                            "targetPort": 80
                        }
                    ],
                    "selector": {
                        "run": "nginx"
                    },
                    "type": "LoadBalancer"
                },
                "status": {
                    "loadBalancer": {}
                }
            }
        }
    }
    count(k8srequiredipfiltering.violation) == 1 with input as payload
}

test_deny_service_with_empty_ip_filtering {
    payload := {
        "kind": "AdmissionReview",
        "request": {
            "kind": {
                "kind": "Service",
                "version": "v1"
            },
            "object": {
                "metadata": {
                    "name": "nginx",
                    "creationTimestamp": null,
                    "labels": {
                        "run": "nginx"
                    }
                },
                "spec": {
                    "ports": [
                        {
                            "protocol": "TCP",
                            "port": 80,
                            "targetPort": 80
                        }
                    ],
                    "selector": {
                        "run": "nginx"
                    },
                    "type": "LoadBalancer",
                    "loadBalancerSourceRanges": []
                },
                "status": {
                    "loadBalancer": {}
                }
            }
        }
    }
    count(k8srequiredipfiltering.violation) == 1 with input as payload
}

test_deny_service_without_filtering_if_annotation_is_defined_with_wrong_value {
    payload := {
        "kind": "AdmissionReview",
        "request": {
            "kind": {
                "kind": "Service",
                "version": "v1"
            },
            "object": {
                "metadata": {
                    "name": "nginx",
                    "creationTimestamp": null,
                    "labels": {
                        "run": "nginx"
                    },
                    "annotations": {
                        "security.k8s.io/allow-no-ip-filtering": "yes"
                    }
                },
                "spec": {
                    "ports": [
                        {
                            "protocol": "TCP",
                            "port": 80,
                            "targetPort": 80
                        }
                    ],
                    "selector": {
                        "run": "nginx"
                    },
                    "type": "LoadBalancer",
                    "loadBalancerSourceRanges": []
                },
                "status": {
                    "loadBalancer": {}
                }
            }
        }
    }
    count(k8srequiredipfiltering.violation) == 1 with input as payload
}

test_allow_service_without_filtering_if_annotation_is_defined {
    payload := {
        "kind": "AdmissionReview",
        "request": {
            "kind": {
                "kind": "Service",
                "version": "v1"
            },
            "object": {
                "metadata": {
                    "name": "nginx",
                    "creationTimestamp": null,
                    "labels": {
                        "run": "nginx"
                    },
                    "annotations": {
                        "security.k8s.io/allow-no-ip-filtering": "true"
                    }
                },
                "spec": {
                    "ports": [
                        {
                            "protocol": "TCP",
                            "port": 80,
                            "targetPort": 80
                        }
                    ],
                    "selector": {
                        "run": "nginx"
                    },
                    "type": "LoadBalancer",
                    "loadBalancerSourceRanges": []
                },
                "status": {
                    "loadBalancer": {}
                }
            }
        }
    }
    count(k8srequiredipfiltering.violation) == 0 with input as payload
}

test_allow_service_with_filtering_ips {
    payload := {
        "kind": "AdmissionReview",
        "request": {
            "kind": {
                "kind": "Service",
                "version": "v1"
            },
            "object": {
                "metadata": {
                    "name": "nginx",
                    "creationTimestamp": null,
                    "labels": {
                        "run": "nginx"
                    }
                },
                "spec": {
                    "ports": [
                        {
                            "protocol": "TCP",
                            "port": 80,
                            "targetPort": 80
                        }
                    ],
                    "selector": {
                        "run": "nginx"
                    },
                    "type": "LoadBalancer",
                    "loadBalancerSourceRanges": ["1.2.3.4/32"]
                },
                "status": {
                    "loadBalancer": {}
                }
            }
        }
    }
    count(k8srequiredipfiltering.violation) == 0 with input as payload
}
