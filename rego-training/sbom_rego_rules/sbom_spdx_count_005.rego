#
# METADATA
# title: Verify all files in the SPDX SBOM have at least 2 checksums.
# description: >-
#   Verify all files in the SPDX SBOM have at least 2 checksums.
# custom:
#   short_name: sbom_spdx_count_005
#   failure_msg: Policy validation failed
#
package sbom_spdx_count_005

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some file in sbom.files
    count(file.checksums) < 2
    result := sprintf("File %s has only %d checksums, expected at least 2", [file.fileName, count(file.checksums)])
}
