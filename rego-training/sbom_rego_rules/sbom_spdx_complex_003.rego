#
# METADATA
# title: Verify the SPDX SBOM name contains '@sha256:'.
# description: >-
#   Verify the SPDX SBOM name contains '@sha256:'.
# custom:
#   short_name: sbom_spdx_complex_003
#   failure_msg: Policy validation failed
#
package sbom_spdx_complex_003

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    not contains(sbom.name, "@sha256:")
    result := sprintf("SPDX SBOM name %s does not contain @sha256:", [sbom.name])
}
