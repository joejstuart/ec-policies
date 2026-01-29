#
# METADATA
# title: Verify all packages in the SPDX SBOM have a name.
# description: >-
#   Verify all packages in the SPDX SBOM have a name.
# custom:
#   short_name: sbom_spdx_005
#   failure_msg: Policy validation failed
#
package sbom_spdx_005

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    not pkg.name
    result := "Package in SPDX SBOM has no name"
}
