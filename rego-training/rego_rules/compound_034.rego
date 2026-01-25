package compound_034

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have the annotation 'results.tekton.dev/result' set.
# description: >-
#   Verify all tasks in the PipelineRun attestation have the annotation 'results.tekton.dev/result' set.
# custom:
#   short_name: compound_034
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	annotations := task.invocation.environment.annotations
	annotations
	count(annotations) > 0
	not annotations["results.tekton.dev/result"]
	result := sprintf("Task %s does not have annotation results.tekton.dev/result", [task.name])
}
