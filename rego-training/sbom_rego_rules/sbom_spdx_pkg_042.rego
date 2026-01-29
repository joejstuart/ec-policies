#
# METADATA
# title: Verify all packages in the SPDX SBOM have a non-empty name.
# description: >-
#   Verify all packages in the SPDX SBOM have a non-empty name.
# custom:
#   short_name: sbom_spdx_pkg_042
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_042

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.name == ""
    result := "Package in SPDX SBOM has empty name"
}
