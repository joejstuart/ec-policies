#
# METADATA
# title: Verify all packages in the SPDX SBOM have a valid originator format.
# description: >-
#   Verify all packages in the SPDX SBOM have a valid originator format.
# custom:
#   short_name: sbom_spdx_pkg_029
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_029

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.originator != "NOASSERTION"
    not contains(pkg.originator, ":")
    result := sprintf("Package %s has invalid originator format: %s", [pkg.name, pkg.originator])
}
