#
# METADATA
# title: Verify all packages in the SPDX SBOM have unique SPDXIDs.
# description: >-
#   Verify all packages in the SPDX SBOM have unique SPDXIDs.
# custom:
#   short_name: sbom_spdx_pkg_035
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_035

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    pkg_ids := {pkg.SPDXID | some pkg in sbom.packages}
    count(pkg_ids) != count(sbom.packages)
    result := "SPDX SBOM has duplicate package SPDXIDs"
}
