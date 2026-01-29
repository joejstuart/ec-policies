#
# METADATA
# title: Verify all packages in the SPDX SBOM have external references with unique referenceLocators.
# description: >-
#   Verify all packages in the SPDX SBOM have external references with unique referenceLocators.
# custom:
#   short_name: sbom_spdx_pkg_038
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_038

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    ref_locators := {ref.referenceLocator | some ref in pkg.externalRefs}
    count(ref_locators) != count(pkg.externalRefs)
    result := sprintf("Package %s has duplicate external reference locators", [pkg.name])
}
