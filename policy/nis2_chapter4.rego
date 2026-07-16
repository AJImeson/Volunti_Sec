# =============================================================================
# Policy as Code — NIS2 Directive (EU 2022/2555), Chapter IV: Risk Management
# =============================================================================
# Learning-purpose policy for validating Kubernetes manifests with Conftest/OPA.
#
# Chapter IV covers cybersecurity risk-management measures and reporting:
#   Art. 20 — Governance
#   Art. 21 — Cybersecurity risk-management measures (the (a)-(j) list)
#   Art. 23 — Reporting obligations (24h early warning / 72h notification)
#
# This policy implements a *simple subset* of Art. 21(2) as manifest checks:
#   (d) supply chain security      -> deny :latest / untagged images
#   (h) cryptography & encryption  -> deny plaintext Secrets (SealedSecret only)
#   (i) access control             -> deny privileged / root containers
#   (b) incident handling          -> warn if probes are missing
#   (c) business continuity        -> warn if only a single replica
#
# NOT covered here (organizational measures, can't be checked in manifests):
#   (a) risk analysis policies, (f) effectiveness assessment, (g) cyber
#   hygiene training. (e) secure development belongs mostly in CI (image
#   scanning), not in manifests.
#
# Usage:
#   conftest test K3s/ --policy policy/
# =============================================================================

package nis2.chapter4

import rego.v1

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet"}

is_workload if input.kind in workload_kinds

containers contains c if {
	is_workload
	some c in input.spec.template.spec.containers
}

# -----------------------------------------------------------------------------
# Art. 21(2)(d) — Supply chain security
# Images must be pinned to a specific tag so you know exactly what runs.
# -----------------------------------------------------------------------------
deny contains msg if {
	some c in containers
	endswith(c.image, ":latest")
	msg := sprintf(
		"[NIS2 Art.21(2)(d)] %s '%s': container '%s' uses ':latest' — pin a specific image tag",
		[input.kind, input.metadata.name, c.name],
	)
}

deny contains msg if {
	some c in containers
	not contains(c.image, ":")
	msg := sprintf(
		"[NIS2 Art.21(2)(d)] %s '%s': container '%s' has no image tag — pin a specific image tag",
		[input.kind, input.metadata.name, c.name],
	)
}

# -----------------------------------------------------------------------------
# Art. 21(2)(h) — Cryptography and encryption
# No plaintext Secrets in git — this repo uses SealedSecrets, so codify that.
# -----------------------------------------------------------------------------
deny contains msg if {
	input.kind == "Secret"
	msg := sprintf(
		"[NIS2 Art.21(2)(h)] Secret '%s' is stored in plaintext — use a SealedSecret instead",
		[input.metadata.name],
	)
}

# -----------------------------------------------------------------------------
# Art. 21(2)(i) — Access control policies
# Containers must not run privileged or as root.
# -----------------------------------------------------------------------------
deny contains msg if {
	some c in containers
	c.securityContext.privileged == true
	msg := sprintf(
		"[NIS2 Art.21(2)(i)] %s '%s': container '%s' runs privileged — remove 'privileged: true'",
		[input.kind, input.metadata.name, c.name],
	)
}

warn contains msg if {
	some c in containers
	not c.securityContext.runAsNonRoot
	msg := sprintf(
		"[NIS2 Art.21(2)(i)] %s '%s': container '%s' should set 'runAsNonRoot: true'",
		[input.kind, input.metadata.name, c.name],
	)
}

# -----------------------------------------------------------------------------
# Art. 21(2)(b) — Incident handling
# Without probes, Kubernetes cannot detect that a workload is unhealthy.
# -----------------------------------------------------------------------------
warn contains msg if {
	some c in containers
	not c.livenessProbe
	msg := sprintf(
		"[NIS2 Art.21(2)(b)] %s '%s': container '%s' has no livenessProbe — failures go undetected",
		[input.kind, input.metadata.name, c.name],
	)
}

# -----------------------------------------------------------------------------
# Art. 21(2)(c) — Business continuity
# A single replica means any node failure is an outage.
# -----------------------------------------------------------------------------
warn contains msg if {
	is_workload
	object.get(input, ["spec", "replicas"], 1) < 2
	msg := sprintf(
		"[NIS2 Art.21(2)(c)] %s '%s': fewer than 2 replicas — no resilience against node failure",
		[input.kind, input.metadata.name],
	)
}
