# =============================================================================
# Policy as Code — NIS2 Directive (EU 2022/2555), Art. 21(2)(c)
# Business continuity: backup management and disaster recovery
# =============================================================================
# nis2_chapter4.rego can only check that a StatefulSet *declares* a continuity
# strategy via 'nis2.eu/continuity-strategy'. A label is a claim, not a control:
# nothing stopped us from labelling the database 'backup-restore' while no
# backup existed. This policy closes that gap in two directions.
#
#   1. Per-document rules for batch workloads. chapter4's `containers` rule
#      only walks Deployment/StatefulSet/DaemonSet, so CronJobs and Jobs were
#      invisible to the image-pinning and non-root checks — a backup job could
#      have run as root off a floating tag and the gate would have stayed green.
#
#   2. A cross-document rule (conftest --combine) that requires any StatefulSet
#      claiming 'backup-restore' to actually be named by a backup CronJob.
#
# Rules in section 2 only fire when input is an array, which is the shape
# conftest passes under --combine; under normal per-document evaluation they
# are no-ops. Conversely the per-document rules here and in chapter1/chapter4
# are no-ops under --combine (input.kind is undefined on an array), so both
# conftest invocations can safely load this same policy directory.
#
# Usage:
#   conftest test rendered/ --policy policy/ --all-namespaces
#   conftest test rendered/ --policy policy/ --all-namespaces --combine
# =============================================================================

package nis2.continuity

import rego.v1

# -----------------------------------------------------------------------------
# 1. Batch workloads (CronJob / Job) — the coverage gap in chapter4
# -----------------------------------------------------------------------------

# A CronJob nests its pod spec one level deeper than a Job.
batch_containers contains c if {
	input.kind == "CronJob"
	some c in input.spec.jobTemplate.spec.template.spec.containers
}

batch_containers contains c if {
	input.kind == "Job"
	some c in input.spec.template.spec.containers
}

# Art. 21(2)(d) — supply chain security. Same pinning rule as chapter4.
deny contains msg if {
	some c in batch_containers
	endswith(c.image, ":latest")
	msg := sprintf(
		"[NIS2 Art.21(2)(d)] %s '%s': container '%s' uses ':latest' — pin a specific image tag",
		[input.kind, input.metadata.name, c.name],
	)
}

deny contains msg if {
	some c in batch_containers
	not contains(c.image, ":")
	msg := sprintf(
		"[NIS2 Art.21(2)(d)] %s '%s': container '%s' has no image tag — pin a specific image tag",
		[input.kind, input.metadata.name, c.name],
	)
}

# Art. 21(2)(i) — access control. A backup job holds credentials to the entire
# database, so it is exactly the workload that must not run privileged or root.
deny contains msg if {
	some c in batch_containers
	c.securityContext.privileged == true
	msg := sprintf(
		"[NIS2 Art.21(2)(i)] %s '%s': container '%s' runs privileged — remove 'privileged: true'",
		[input.kind, input.metadata.name, c.name],
	)
}

warn contains msg if {
	some c in batch_containers
	not c.securityContext.runAsNonRoot
	msg := sprintf(
		"[NIS2 Art.21(2)(i)] %s '%s': container '%s' should set 'runAsNonRoot: true'",
		[input.kind, input.metadata.name, c.name],
	)
}

# A backup CronJob that does not say what it backs up cannot be matched to the
# workload it protects, which defeats the cross-document check below.
deny contains msg if {
	input.kind == "CronJob"
	labels := object.get(input, ["metadata", "labels"], {})
	labels["nis2.eu/role"] == "backup"
	not labels["nis2.eu/backup-target"]
	msg := sprintf(
		"[NIS2 Art.21(2)(c)] CronJob '%s' is labelled 'nis2.eu/role: backup' but declares no 'nis2.eu/backup-target'",
		[input.metadata.name],
	)
}

# -----------------------------------------------------------------------------
# 2. Cross-document: a declared backup strategy must have a real backup job
# -----------------------------------------------------------------------------
# Under --combine, input is [{"path": ..., "contents": ...}]. `contents` is an
# object for a single-document file and an array for a multi-document one, so
# flatten both shapes.

combined_docs contains d if {
	is_array(input)
	some entry in input
	is_object(entry.contents)
	d := entry.contents
}

combined_docs contains d if {
	is_array(input)
	some entry in input
	is_array(entry.contents)
	some d in entry.contents
}

# Every workload named as the target of a backup CronJob.
backed_up_workloads contains target if {
	some d in combined_docs
	d.kind == "CronJob"
	labels := object.get(d, ["metadata", "labels"], {})
	labels["nis2.eu/role"] == "backup"
	target := labels["nis2.eu/backup-target"]
}

# Art. 21(2)(c) — the claim must be backed by a control.
deny contains msg if {
	some d in combined_docs
	d.kind == "StatefulSet"
	labels := object.get(d, ["metadata", "labels"], {})
	labels["nis2.eu/continuity-strategy"] == "backup-restore"
	not d.metadata.name in backed_up_workloads
	msg := sprintf(
		"[NIS2 Art.21(2)(c)] StatefulSet '%s' declares continuity-strategy 'backup-restore' but no CronJob carries 'nis2.eu/role: backup' with 'nis2.eu/backup-target: %s' — the continuity claim is unverified",
		[d.metadata.name, d.metadata.name],
	)
}
