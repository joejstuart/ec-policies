#
# METADATA
# title: Verify all packages in the SPDX SBOM have a valid licenseConcluded format.
# description: >-
#   Verify all packages in the SPDX SBOM have a valid licenseConcluded format.
# custom:
#   short_name: sbom_spdx_pkg_032
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_032

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.licenseConcluded != "NOASSERTION"
    not contains(pkg.licenseConcluded, "-")
    not startswith(pkg.licenseConcluded, "LicenseRef-")
    result := sprintf("Package %s has invalid licenseConcluded format: %s", [pkg.name, pkg.licenseConcluded])
}
