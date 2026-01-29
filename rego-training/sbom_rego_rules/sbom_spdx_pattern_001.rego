#
# METADATA
# title: Verify all packages in the SPDX SBOM have PURLs containing '@'.
# description: >-
#   Verify all packages in the SPDX SBOM have PURLs containing '@'.
# custom:
#   short_name: sbom_spdx_pattern_001
#   failure_msg: Policy validation failed
#
package sbom_spdx_pattern_001

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some ref in pkg.externalRefs
    ref.referenceType == "purl"
    not contains(ref.referenceLocator, "@")
    result := sprintf("Package %s has PURL without @: %s", [pkg.name, ref.referenceLocator])
}
