#
# METADATA
# title: Verify all packages in the SPDX SBOM have a licenseDeclared.
# description: >-
#   Verify all packages in the SPDX SBOM have a licenseDeclared.
# custom:
#   short_name: sbom_spdx_pkg_008
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_008

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.licenseDeclared == "NOASSERTION"
    result := sprintf("Package %s has no declared license", [pkg.name])
}
