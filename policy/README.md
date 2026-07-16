# Files in Policy directory created with Claude 

# Policy as Code — NIS2

Learning-purpose OPA/Rego policies mapping the [NIS2 Directive (EU 2022/2555)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj)
onto the Kubernetes manifests in `K3s/`.

## Files

| File | Covers |
|------|--------|
| `nis2_chapter1.rego` | Chapter I — General provisions (scope, entity classification, definitions) |
| `nis2_chapter4.rego` | Chapter IV — Risk-management measures (subset of Art. 21(2): supply chain, encryption, access control, incident handling, continuity) |

## How it works

Chapter I of NIS2 is about *who* is in scope and *how* entities are classified —
not technical controls. The policy therefore requires each workload
(Deployment / StatefulSet / DaemonSet) to declare its scope via labels:

```yaml
metadata:
  labels:
    nis2.eu/entity-classification: important   # Art. 3 — essential | important | out-of-scope
    nis2.eu/sector: digital-infrastructure     # Art. 2 — Annex I/II sector
    nis2.eu/owner: team-burgundy               # Art. 6 — accountable entity (warn only)
```

## Running locally

Requires [Conftest](https://www.conftest.dev/):

```bash
conftest test K3s/ --policy policy/
```

## Running in CI (optional)

Add a job to `.gitlab-ci.yml`:

```yaml
policy-check:
  stage: test
  image: openpolicyagent/conftest:latest
  script:
    - conftest test K3s/ --policy policy/
```
