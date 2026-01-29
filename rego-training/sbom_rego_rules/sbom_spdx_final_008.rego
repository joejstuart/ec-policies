#
# METADATA
# title: Verify all packages in the SPDX SBOM have external references with referenceCategory in allowed categories.
# description: >-
#   Verify all packages in the SPDX SBOM have external references with referenceCategory in allowed categories.
# custom:
#   short_name: sbom_spdx_final_008
#   failure_msg: Policy validation failed
#
package sbom_spdx_final_008

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some ref in pkg.externalRefs
    not (ref.referenceCategory in ["SECURITY", "PACKAGE_MANAGER", "PERSISTENT_ID", "OTHER"])
    result := sprintf("Package %s has disallowed referenceCategory: %s", [pkg.name, ref.referenceCategory])
}
