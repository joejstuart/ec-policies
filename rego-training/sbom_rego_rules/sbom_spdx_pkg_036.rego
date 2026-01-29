#
# METADATA
# title: Verify all packages in the SPDX SBOM have unique names.
# description: >-
#   Verify all packages in the SPDX SBOM have unique names.
# custom:
#   short_name: sbom_spdx_pkg_036
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_036

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    pkg_names := {pkg.name | some pkg in sbom.packages}
    count(pkg_names) != count(sbom.packages)
    result := "SPDX SBOM has duplicate package names"
}
