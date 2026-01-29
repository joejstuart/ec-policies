#
# METADATA
# title: Verify all packages in the SPDX SBOM have a copyrightText.
# description: >-
#   Verify all packages in the SPDX SBOM have a copyrightText.
# custom:
#   short_name: sbom_spdx_pkg_010
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_010

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.copyrightText == "NOASSERTION"
    result := sprintf("Package %s has no copyright text", [pkg.name])
}
