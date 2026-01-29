#
# METADATA
# title: Verify all files in the SPDX SBOM have checksums with unique algorithms.
# description: >-
#   Verify all files in the SPDX SBOM have checksums with unique algorithms.
# custom:
#   short_name: sbom_spdx_file_012
#   failure_msg: Policy validation failed
#
package sbom_spdx_file_012

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some file in sbom.files
    chk_algorithms := {chk.algorithm | some chk in file.checksums}
    count(chk_algorithms) != count(file.checksums)
    result := sprintf("File %s has duplicate checksum algorithms", [file.fileName])
}
