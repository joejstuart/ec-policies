#
# METADATA
# title: Verify all files in the SPDX SBOM have checksums with valid checksumValue.
# description: >-
#   Verify all files in the SPDX SBOM have checksums with valid checksumValue.
# custom:
#   short_name: sbom_spdx_file_007
#   failure_msg: Policy validation failed
#
package sbom_spdx_file_007

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some file in sbom.files
    some chk in file.checksums
    not chk.checksumValue
    result := sprintf("File %s has checksum with no checksumValue", [file.fileName])
}
