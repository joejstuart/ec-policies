#
# METADATA
# title: Verify the SPDX SBOM has packages from at least one package manager type.
# description: >-
#   Verify the SPDX SBOM has packages from at least one package manager type.
# custom:
#   short_name: sbom_spdx_complex_008
#   failure_msg: Policy validation failed
#
package sbom_spdx_complex_008

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    pkg_managers := {ref.referenceLocator | some pkg in sbom.packages; some ref in pkg.externalRefs; ref.referenceCategory == "PACKAGE_MANAGER"}
    count(pkg_managers) == 0
    result := "SPDX SBOM has no packages from package managers"
}
