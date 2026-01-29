#
# METADATA
# title: Verify all packages in the SPDX SBOM have a valid supplier format.
# description: >-
#   Verify all packages in the SPDX SBOM have a valid supplier format.
# custom:
#   short_name: sbom_spdx_pkg_028
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_028

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.supplier != "NOASSERTION"
    not contains(pkg.supplier, ":")
    result := sprintf("Package %s has invalid supplier format: %s", [pkg.name, pkg.supplier])
}
