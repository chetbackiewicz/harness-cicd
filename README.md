# vuln-notes-api

A deliberately vulnerable Go microservice used as a target for CI/CD security
scans (SAST, SCA, Secret Detection). Pure stdlib + an in-memory store, so it compiles in
seconds. 

## Run

```bash
go run .                                 # listens on :8080 (override with ADDR)
curl -s http://localhost:8080/health
```

## Test

```bash
go test ./...                            # 47 tests, ~250ms
```


## Container build

```dockerfile
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/vuln-notes-api .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/vuln-notes-api /vuln-notes-api
EXPOSE 8080
ENTRYPOINT ["/vuln-notes-api"]
```

## CI/CD Pipeline (`CI_CD_Vuln_Api`)

The Harness pipeline has four stages that run in sequence:

| Stage | Type | Purpose |
| ----- | ---- | ------- |
| `BuildAndTest` | CI | Compile and run Go tests via the `Build_and_Test` template |
| `Security_Scan` | **SecurityTests** | SAST (Semgrep), SCA (OWASP), and secrets (Gitleaks) scans |
| `PushImage` | CI | Build and push Docker image to `chetback/vuln_api` on DockerHub and Updates the values.yaml with updated image tag, trigger GitOps update |

### Security scanning & OPA governance

The `Security_Scan` stage uses `type: SecurityTests`, which enables native Harness STO ↔ OPA integration. Scan results are automatically submitted to the Harness OPA server as `securityTestData` at pipeline run time — no explicit Policy step is required in the stage.

An OPA Policy Set is applied to the **Security Tests** entity on the **On Step** event. The policy (package `securityTests`) blocks the pipeline if any Critical or High is found, and >10 Medium Severity vulnerabilities are found.

```rego
# Adjust allowed thresholds as needed
max_critical := 0
max_high := 0
max_medium := 5

deny[msg] {
    input[i].name == "output"
    count := to_number(input[i].outcome.outputVariables.CRITICAL)
    count > max_critical
    msg := sprintf("Pipeline blocked: %d Critical vulnerabilities exceeds threshold of %d", [count, max_critical])
}

deny[msg] {
    input[i].name == "output"
    count := to_number(input[i].outcome.outputVariables.HIGH)
    count > max_high
    msg := sprintf("Pipeline blocked: %d High vulnerabilities exceeds threshold of %d", [count, max_high])
}

deny[msg] {
    input[i].name == "output"
    count := to_number(input[i].outcome.outputVariables.MEDIUM)
    count > max_medium
    msg := sprintf("Pipeline blocked: %d Medium vulnerabilities exceeds threshold of %d", [count, max_medium])
}
```

To allow the pipeline to pass despite known findings (e.g. during triage), raise the threshold value or temporarily remove the entry from `deny_list` in the Policy.

## Minimizing AKS cost (stop/start the cluster)

The AKS cluster (`harness-lab` in resource group `harness`) bills for its node VMs while running.
The control plane is on the Free tier ($0). To avoid paying for nodes when you're not using the
cluster, **stop** it at the end of a session and **start** it at the beginning. `az aks stop`
deallocates all node VMs (compute billing stops) while preserving the cluster, node pool, disks,
GitOps agent, and workloads.


```bash
# End of session — stop the cluster (deallocate nodes)
az aks stop  -g harness -n harness-lab --no-wait

# Start of session — start the cluster (re-allocates nodes, pods reschedule)
az aks start -g harness -n harness-lab

# Check current power state (Running | Stopped)
az aks show -g harness -n harness-lab --query powerState.code -o tsv
```

After `start`, give the nodes a minute or two to become `Ready` and for the Harness delegate,
GitOps agent, and `vuln-api` pods to reschedule:

```bash
kubectl get nodes
kubectl get pods -n harness-delegate-ng
```

