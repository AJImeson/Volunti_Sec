# Files in Policy directory created with Claude 

# Policy as Code — NIS2

Learning-purpose OPA/Rego policies mapping the [NIS2 Directive (EU 2022/2555)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj)
onto the Kubernetes manifests in `K3s/`.

## Files

| File | Covers |
|------|--------|
| `nis2_chapter1.rego` | Chapter I — General provisions (scope, entity classification, definitions) |
| `nis2_chapter4.rego` | Chapter IV — Risk-management measures (subset of Art. 21(2): supply chain, encryption, access control, incident handling, continuity) |
| `nis2_continuity.rego` | Art. 21(2)(c) — backup management: extends the image/root checks to CronJob/Job, and verifies a declared backup strategy has a real backup job behind it |

### Claims vs. controls

`nis2_chapter4.rego` can only check that a StatefulSet *declares* a continuity
strategy through `nis2.eu/continuity-strategy`. A label is a claim, not a
control — nothing stopped the database being labelled `backup-restore` while no
backup existed. `nis2_continuity.rego` closes that with a cross-document rule:
a StatefulSet claiming `backup-restore` must be named by a CronJob carrying
`nis2.eu/role: backup` and a matching `nis2.eu/backup-target`. Deleting the
backup job now turns the pipeline red.

That rule needs to see every manifest at once, so CI runs conftest twice — once
per-document and once with `--combine`. The two rule sets are mutually
inert (the combine rules require an array input, the per-document rules require
an object), so one `policy/` directory serves both passes.

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

The manifests are `envsubst` templates, so render them first — conftest must
validate the same YAML that reaches the cluster, not `image: .../backend:${IMAGE_TAG}`:

```bash
export IMAGE_TAG=local PREFIX=""
mkdir -p rendered
for f in $(find K3s -name '*.yaml'); do
  envsubst '${PREFIX} ${IMAGE_TAG} ${ASPNET_ENV} ${FRONTEND_HOST} ${BACKEND_HOST} ${ADMINER_HOST} ${BACKEND_URL}' \
    < "$f" > "rendered/$(echo "$f" | tr '/' '_')"
done

conftest test rendered/ --policy policy/ --all-namespaces
conftest test rendered/ --policy policy/ --all-namespaces --combine
```

`--all-namespaces` is required: the rules live in packages `nis2.chapter1` /
`nis2.chapter4` / `nis2.continuity`, and conftest only evaluates the `main`
package by default — without the flag it reports "0 tests" and passes trivially.

## Running in CI

Already wired as an enforcing gate in both
`.github/workflows/policy-check.yml` (GitHub Actions, the live CI) and
`policy/policy-check.yml` (GitLab). A `deny` fails the job; `warn` only prints.
