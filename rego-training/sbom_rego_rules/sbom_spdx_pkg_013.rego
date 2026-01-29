#
# METADATA
# title: Verify all packages in the SPDX SBOM have a PURL external reference.
# description: >-
#   Verify all packages in the SPDX SBOM have a PURL external reference.
# custom:
#   short_name: sbom_spdx_pkg_013
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_013

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    count([ref | some ref in pkg.externalRefs; ref.referenceType == "purl"]) == 0
    result := sprintf("Package %s has no PURL external reference", [pkg.name])
}
