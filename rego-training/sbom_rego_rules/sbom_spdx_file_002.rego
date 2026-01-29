#
# METADATA
# title: Verify all files in the SPDX SBOM have an SPDXID.
# description: >-
#   Verify all files in the SPDX SBOM have an SPDXID.
# custom:
#   short_name: sbom_spdx_file_002
#   failure_msg: Policy validation failed
#
package sbom_spdx_file_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some file in sbom.files
    not file.SPDXID
    result := sprintf("File %s has no SPDXID", [file.fileName])
}
