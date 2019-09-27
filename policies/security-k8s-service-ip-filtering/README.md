# Service without IP filtering

This first policy make a check on all servcies object and deny the request when a service of type `LoadBalancer` does not have the property `spec.loadBalancerSourceRanges`

Reference: https://github.com/open-policy-agent/gatekeeper

## How to test the policies

When you have wrote unit test for your policies, you can check all your test cases by running the following command:

```bash
opa test -v src/
```

You need to install the `open agent policy` cli.

## Deploy

When `gatekeeper` is deployed on your cluster you can apply the policy by running the following commands:

```bash
kubectl apply -f templates/template.yaml
kubectl apply -f constraints/constraint.yaml
```

## Tests

### Bad resources

```bash
kubectl apply -f tests/bad/bad-svc-without-ip-filtering.yaml
```

### Good resources

```bash
kubectl apply -f tests/good/good-svc-with-ip-filtering.yaml
kubectl apply -f tests/good/bad-svc-but-bypass-annotation.yaml
```

