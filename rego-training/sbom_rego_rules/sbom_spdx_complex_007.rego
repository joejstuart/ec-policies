#
# METADATA
# title: Verify all packages in the SPDX SBOM with versionInfo starting with 'v' have valid version format.
# description: >-
#   Verify all packages in the SPDX SBOM with versionInfo starting with 'v' have valid version format.
# custom:
#   short_name: sbom_spdx_complex_007
#   failure_msg: Policy validation failed
#
package sbom_spdx_complex_007

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    startswith(pkg.versionInfo, "v")
    version_num := trim_prefix(pkg.versionInfo, "v")
    not contains(version_num, ".")
    result := sprintf("Package %s has invalid version format: %s", [pkg.name, pkg.versionInfo])
}
