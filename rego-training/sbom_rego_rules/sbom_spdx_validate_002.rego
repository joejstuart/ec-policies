#
# METADATA
# title: Verify all packages in the SPDX SBOM have checksumValue with valid length for SHA1.
# description: >-
#   Verify all packages in the SPDX SBOM have checksumValue with valid length for SHA1.
# custom:
#   short_name: sbom_spdx_validate_002
#   failure_msg: Policy validation failed
#
package sbom_spdx_validate_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some chk in pkg.checksums
    chk.algorithm == "SHA1"
    count(chk.checksumValue) != 40
    result := sprintf("Package %s has SHA1 checksum with invalid length: %d", [pkg.name, count(chk.checksumValue)])
}
