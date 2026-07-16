# =============================================================================
# Policy as Code — NIS2 Directive (EU 2022/2555), Chapter I: General Provisions
# =============================================================================
# Learning-purpose policy for validating Kubernetes manifests with Conftest/OPA.
#
# Chapter I of NIS2 covers:
#   Art. 1 — Subject matter (a high common level of cybersecurity across the EU)
#   Art. 2 — Scope (which entities the directive applies to)
#   Art. 3 — Essential and important entities (classification)
#   Art. 4 — Sector-specific Union legal acts (lex specialis)
#   Art. 5 — Minimum harmonisation
#   Art. 6 — Definitions
#
# Chapter I defines WHO is in scope and HOW entities are classified — it does
# not prescribe technical controls (those come in Chapter IV). So this policy
# enforces that every workload *declares* its NIS2 scope metadata via labels,
# making classification auditable directly from the manifests.
#
# Usage:
#   conftest test K3s/ --policy policy/
# =============================================================================

package nis2.chapter1

import rego.v1

# Workload kinds that must carry NIS2 scope metadata
workload_kinds := {"Deployment", "StatefulSet", "DaemonSet"}

is_workload if input.kind in workload_kinds

labels := object.get(input, ["metadata", "labels"], {})

# -----------------------------------------------------------------------------
# Art. 3 — Essential and important entities
# Every workload must declare which entity classification it operates under.
# -----------------------------------------------------------------------------
valid_classifications := {"essential", "important", "out-of-scope"}

deny contains msg if {
	is_workload
	not labels["nis2.eu/entity-classification"]
	msg := sprintf(
		"[NIS2 Art.3] %s '%s' is missing label 'nis2.eu/entity-classification' (essential | important | out-of-scope)",
		[input.kind, input.metadata.name],
	)
}

deny contains msg if {
	is_workload
	classification := labels["nis2.eu/entity-classification"]
	not classification in valid_classifications
	msg := sprintf(
		"[NIS2 Art.3] %s '%s' has invalid classification '%s' — must be one of: essential, important, out-of-scope",
		[input.kind, input.metadata.name, classification],
	)
}

# -----------------------------------------------------------------------------
# Art. 2 — Scope
# In-scope workloads must declare the sector they belong to (Annex I / II of
# the directive lists the sectors, e.g. energy, transport, health, digital
# infrastructure, ICT service management).
# -----------------------------------------------------------------------------
deny contains msg if {
	is_workload
	labels["nis2.eu/entity-classification"] in {"essential", "important"}
	not labels["nis2.eu/sector"]
	msg := sprintf(
		"[NIS2 Art.2] %s '%s' is classified in-scope but missing label 'nis2.eu/sector' (see Annex I/II sectors)",
		[input.kind, input.metadata.name],
	)
}

# -----------------------------------------------------------------------------
# Art. 6 — Definitions ("network and information system", "security of ...")
# In-scope workloads must name an accountable owner, so the "entity" behind
# each network and information system is identifiable.
# -----------------------------------------------------------------------------
warn contains msg if {
	is_workload
	labels["nis2.eu/entity-classification"] in {"essential", "important"}
	not labels["nis2.eu/owner"]
	msg := sprintf(
		"[NIS2 Art.6] %s '%s' should declare label 'nis2.eu/owner' to identify the accountable entity",
		[input.kind, input.metadata.name],
	)
}
