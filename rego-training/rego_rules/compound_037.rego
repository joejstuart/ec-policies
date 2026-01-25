package compound_037

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the annotation 'results.tekton.dev/childReadyForDeletion' set to 'true'.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the annotation 'results.tekton.dev/childReadyForDeletion' set to 'true'.
# custom:
#   short_name: compound_037
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	annotations := task.invocation.environment.annotations
	annotations["results.tekton.dev/childReadyForDeletion"] != "true"
	result := sprintf("Task %s annotation results.tekton.dev/childReadyForDeletion is not true", [task.name])
}
