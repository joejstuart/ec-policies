#
# METADATA
# title: Verify all packages in the SPDX SBOM have an originator.
# description: >-
#   Verify all packages in the SPDX SBOM have an originator.
# custom:
#   short_name: sbom_spdx_pkg_007
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_007

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.originator == "NOASSERTION"
    result := sprintf("Package %s has no originator", [pkg.name])
}
