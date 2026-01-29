#
# METADATA
# title: Verify all packages in the SPDX SBOM have at least 2 checksums.
# description: >-
#   Verify all packages in the SPDX SBOM have at least 2 checksums.
# custom:
#   short_name: sbom_spdx_count_004
#   failure_msg: Policy validation failed
#
package sbom_spdx_count_004

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    count(pkg.checksums) < 2
    result := sprintf("Package %s has only %d checksums, expected at least 2", [pkg.name, count(pkg.checksums)])
}
