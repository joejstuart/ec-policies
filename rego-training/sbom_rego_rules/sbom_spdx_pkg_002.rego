#
# METADATA
# title: Verify all packages in the SPDX SBOM have an SPDXID.
# description: >-
#   Verify all packages in the SPDX SBOM have an SPDXID.
# custom:
#   short_name: sbom_spdx_pkg_002
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    not pkg.SPDXID
    result := sprintf("Package %s has no SPDXID", [pkg.name])
}
