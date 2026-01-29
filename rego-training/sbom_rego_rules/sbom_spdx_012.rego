#
# METADATA
# title: Verify the SPDX SBOM has creation info with a created timestamp.
# description: >-
#   Verify the SPDX SBOM has creation info with a created timestamp.
# custom:
#   short_name: sbom_spdx_012
#   failure_msg: Policy validation failed
#
package sbom_spdx_012

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    not sbom.creationInfo.created
    result := "SPDX SBOM has no creation timestamp"
}
