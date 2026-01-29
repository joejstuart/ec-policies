#
# METADATA
# title: Verify all packages in the SPDX SBOM have a supplier.
# description: >-
#   Verify all packages in the SPDX SBOM have a supplier.
# custom:
#   short_name: sbom_spdx_pkg_006
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_006

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.supplier == "NOASSERTION"
    result := sprintf("Package %s has no supplier", [pkg.name])
}
