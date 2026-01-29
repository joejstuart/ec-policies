#
# METADATA
# title: Verify all packages in the SPDX SBOM have a valid licenseDeclared format.
# description: >-
#   Verify all packages in the SPDX SBOM have a valid licenseDeclared format.
# custom:
#   short_name: sbom_spdx_pkg_031
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_031

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.licenseDeclared != "NOASSERTION"
    not contains(pkg.licenseDeclared, "-")
    not startswith(pkg.licenseDeclared, "LicenseRef-")
    result := sprintf("Package %s has invalid licenseDeclared format: %s", [pkg.name, pkg.licenseDeclared])
}
