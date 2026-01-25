package compound_035

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the annotation 'results.tekton.dev/record' set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the annotation 'results.tekton.dev/record' set.
# custom:
#   short_name: compound_035
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	annotations := task.invocation.environment.annotations
	annotations
	count(annotations) > 0
	not annotations["results.tekton.dev/record"]
	result := sprintf("Task %s does not have annotation results.tekton.dev/record", [task.name])
}
