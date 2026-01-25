package compound_036

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the annotation 'results.tekton.dev/stored' set to 'true'.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the annotation 'results.tekton.dev/stored' set to 'true'.
# custom:
#   short_name: compound_036
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	annotations := task.invocation.environment.annotations
	annotations["results.tekton.dev/stored"] != "true"
	result := sprintf("Task %s annotation results.tekton.dev/stored is not true", [task.name])
}
