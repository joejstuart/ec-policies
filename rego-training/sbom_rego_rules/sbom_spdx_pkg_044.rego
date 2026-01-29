#
# METADATA
# title: Verify all packages in the SPDX SBOM have external references with referenceType in allowed types.
# description: >-
#   Verify all packages in the SPDX SBOM have external references with referenceType in allowed types.
# custom:
#   short_name: sbom_spdx_pkg_044
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_044

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some ref in pkg.externalRefs
    not (ref.referenceType in ["purl", "cpe23Type", "swid", "maven-central", "npm", "nuget", "pypi", "gem", "other"])
    result := sprintf("Package %s has disallowed referenceType: %s", [pkg.name, ref.referenceType])
}
