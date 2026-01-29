#
# METADATA
# title: Verify the SPDX SBOM has dataLicense set to 'CC0-1.0'.
# description: >-
#   Verify the SPDX SBOM has dataLicense set to 'CC0-1.0'.
# custom:
#   short_name: sbom_spdx_field_001
#   failure_msg: Policy validation failed
#
package sbom_spdx_field_001

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    sbom.dataLicense != "CC0-1.0"
    result := sprintf("SPDX SBOM has incorrect dataLicense: %s", [sbom.dataLicense])
}
