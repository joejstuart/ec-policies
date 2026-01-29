#
# METADATA
# title: Verify all packages in the SPDX SBOM have a licenseConcluded.
# description: >-
#   Verify all packages in the SPDX SBOM have a licenseConcluded.
# custom:
#   short_name: sbom_spdx_pkg_009
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_009

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.licenseConcluded == "NOASSERTION"
    result := sprintf("Package %s has no concluded license", [pkg.name])
}
