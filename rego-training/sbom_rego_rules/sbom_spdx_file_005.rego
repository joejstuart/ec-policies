#
# METADATA
# title: Verify all files in the SPDX SBOM have a valid SPDXID format.
# description: >-
#   Verify all files in the SPDX SBOM have a valid SPDXID format.
# custom:
#   short_name: sbom_spdx_file_005
#   failure_msg: Policy validation failed
#
package sbom_spdx_file_005

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some file in sbom.files
    not startswith(file.SPDXID, "SPDXRef-")
    result := sprintf("File %s has invalid SPDXID format: %s", [file.fileName, file.SPDXID])
}
