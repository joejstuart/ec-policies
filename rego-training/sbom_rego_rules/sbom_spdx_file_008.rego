#
# METADATA
# title: Verify all files in the SPDX SBOM have a SHA1 checksum.
# description: >-
#   Verify all files in the SPDX SBOM have a SHA1 checksum.
# custom:
#   short_name: sbom_spdx_file_008
#   failure_msg: Policy validation failed
#
package sbom_spdx_file_008

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some file in sbom.files
    count([chk | some chk in file.checksums; chk.algorithm == "SHA1"]) == 0
    result := sprintf("File %s has no SHA1 checksum", [file.fileName])
}
