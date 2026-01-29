#
# METADATA
# title: Verify all packages in the SPDX SBOM have checksums.
# description: >-
#   Verify all packages in the SPDX SBOM have checksums.
# custom:
#   short_name: sbom_spdx_pkg_016
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_016

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    count(pkg.checksums) == 0
    result := sprintf("Package %s has no checksums", [pkg.name])
}
