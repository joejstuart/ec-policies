#
# METADATA
# title: Verify the SPDX SBOM has a dataLicense.
# description: >-
#   Verify the SPDX SBOM has a dataLicense.
# custom:
#   short_name: sbom_spdx_doc_005
#   failure_msg: Policy validation failed
#
package sbom_spdx_doc_005

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    sbom.dataLicense != "CC0-1.0"
    result := sprintf("SPDX SBOM has invalid dataLicense: %s", [sbom.dataLicense])
}
