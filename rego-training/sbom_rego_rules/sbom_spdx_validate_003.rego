#
# METADATA
# title: Verify all files in the SPDX SBOM have checksumValue with valid length for SHA256.
# description: >-
#   Verify all files in the SPDX SBOM have checksumValue with valid length for SHA256.
# custom:
#   short_name: sbom_spdx_validate_003
#   failure_msg: Policy validation failed
#
package sbom_spdx_validate_003

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some file in sbom.files
    some chk in file.checksums
    chk.algorithm == "SHA256"
    count(chk.checksumValue) != 64
    result := sprintf("File %s has SHA256 checksum with invalid length: %d", [file.fileName, count(chk.checksumValue)])
}
