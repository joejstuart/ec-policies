#
# METADATA
# title: Verify all packages in the SPDX SBOM have at least one external reference.
# description: >-
#   Verify all packages in the SPDX SBOM have at least one external reference.
# custom:
#   short_name: sbom_spdx_pkg_012
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_012

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    count(pkg.externalRefs) == 0
    result := sprintf("Package %s has no external references", [pkg.name])
}
