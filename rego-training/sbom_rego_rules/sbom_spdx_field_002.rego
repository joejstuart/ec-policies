#
# METADATA
# title: Verify all packages in the SPDX SBOM have filesAnalyzed set to boolean.
# description: >-
#   Verify all packages in the SPDX SBOM have filesAnalyzed set to boolean.
# custom:
#   short_name: sbom_spdx_field_002
#   failure_msg: Policy validation failed
#
package sbom_spdx_field_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.filesAnalyzed != true
    pkg.filesAnalyzed != false
    result := sprintf("Package %s has invalid filesAnalyzed value", [pkg.name])
}
