package single_key_026

import rego.v1

# METADATA
# title: Verify the build task has the annotation 'build.appstudio.openshift.io/repo' set.
# description: >-
#   Verify the build task has the annotation 'build.appstudio.openshift.io/repo' set.
# custom:
#   short_name: single_key_026
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	annotations := task.invocation.environment.annotations
	annotations
	count(annotations) > 0
	not annotations["build.appstudio.openshift.io/repo"]
	result := "Build task does not have annotation build.appstudio.openshift.io/repo"
}
