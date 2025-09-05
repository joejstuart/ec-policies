#
# METADATA
# title: OLM Release
# description: >-
#   Release-specific checks for Operator Lifecycle Manager (OLM) bundles.
#   These rules are enforced only for "release", "production", or "staging"
#   pipelines, as determined by the pipeline_intention rule data.
#
package olm_release

import rego.v1

import data.lib
import data.lib.image

# METADATA
# title: Unpinned images in input snapshot
# description: >-
#   Check the input snapshot for the presence of unpinned image references.
#   Unpinned image pull references are references to images
#   that do not contain a digest -- uniquely identifying the version of
#   the image being pulled.
# custom:
#   short_name: unpinned_snapshot_references
#   pipeline_intention:
#   - release
#   - production
#   - staging
#   failure_msg: The %q image reference is not pinned in the input snapshot.
#   solution: >-
#     Update the input snapshot replacing the unpinned image reference with pinned image
#     reference. Pinned image reference contains the image digest.
#   collections:
#   - redhat
#   effective_on: 2024-08-15T00:00:00Z
#
deny contains result if {
	lib.pipeline_intention_match(rego.metadata.chain())

	input_image = image.parse(input.image.ref)
	components := input.snapshot.components
	some component in components
	parsed_image := image.parse(component.containerImage)
	parsed_image.repo == input_image.repo
	parsed_image.digest == "" # unpinned image references have no digest

	result := lib.result_helper_with_term(rego.metadata.chain(), [image.str(parsed_image)], image.str(parsed_image))
}

# METADATA
# title: Unpinned related images for a component
# description: >-
#   Check the input image for the presence of related images.
#   Ensure all related image references include a digest.
# custom:
#   short_name: unpinned_related_images
#   pipeline_intention:
#   - release
#   - production
#   - staging
#   failure_msg: "%d related images are not pinned with a digest: %s."
#   solution: >-
#     Update the related images replacing the unpinned image reference
#     with pinned image reference. Pinned image reference contains the image digest
#   collections:
#   - redhat
#
deny contains result if {
	lib.pipeline_intention_match(rego.metadata.chain())

	unpinned_related_images := [related |
		some related in _related_images_not_in_snapshot

		# If the image ref is not pinned this will be an empty string
		related.digest == ""
	]

	# If any are unpinned we produce the violation
	count(unpinned_related_images) > 0

	unpinned_refs := [_image_ref(r) | some r in unpinned_related_images]

	result := lib.result_helper(rego.metadata.chain(), [count(unpinned_related_images), concat(", ", unpinned_refs)])
}

# METADATA
# title: Unable to access related images for a component
# description: >-
#   Check the input image for the presence of related images.
#   Ensure that all images are accessible.
# custom:
#   short_name: inaccessible_related_images
#   pipeline_intention:
#   - release
#   - production
#   - staging
#   failure_msg: The %q related image reference is not accessible.
#   solution: >-
#     Ensure all related images are available. The related images are defined by
#     an file containing a json array attached to the validated image. The digest
#     of the attached file is pulled from the RELATED_IMAGES_DIGEST result.
#   collections:
#   - redhat
#   effective_on: 2025-03-10T00:00:00Z
#
deny contains result if {
	lib.pipeline_intention_match(rego.metadata.chain())

	some unmatched_image in _related_images_not_in_snapshot
	unmatched_ref := _image_ref(unmatched_image)

	# Add a check here to ensure unmatched_ref is not empty or malformed
	unmatched_ref != ""

	not ec.oci.descriptor(unmatched_ref)

	result := lib.result_helper_with_term(rego.metadata.chain(), [unmatched_ref], unmatched_ref)
}

# METADATA
# title: Unmapped images in OLM bundle
# description: >-
#   Check the OLM bundle image for the presence of unmapped image references.
#   Unmapped image pull references are references to images found in
#   link:https://osbs.readthedocs.io/en/latest/users.html#pullspec-locations[varying
#   locations] that are either not in the RPA about to be released or not accessible
#   already.
# custom:
#   short_name: unmapped_references
#   pipeline_intention:
#   - release
#   - production
#   - staging
#   failure_msg: The %q CSV image reference is not in the snapshot or accessible.
#   solution: >-
#     Add the missing image to the snapshot or check if the CSV pullspec
#     is valid and accessible.
#   collections:
#   - redhat
#   effective_on: 2024-08-15T00:00:00Z
deny contains result if {
	lib.pipeline_intention_match(rego.metadata.chain())

	snapshot_components := input.snapshot.components
	component_images_digests := [component_image.digest |
		some component in snapshot_components
		component_image := image.parse(component.containerImage)
	]

	some manifest in _csv_manifests
	all_image_refs := all_image_ref(manifest)
	unmatched_image_refs := [image |
		some image in all_image_refs
		not image.ref.digest in component_images_digests
	]

	some unmatched_image in unmatched_image_refs
	not ec.oci.image_manifest(image.str(unmatched_image.ref))

	# regal ignore:line-length
	result := lib.result_helper_with_term(rego.metadata.chain(), [image.str(unmatched_image.ref)], image.str(unmatched_image.ref))
}

# Helper functions (copied from original olm.rego)
_related_images_not_in_snapshot := [related_image.ref |
	snapshot_components := input.snapshot.components
	component_images_digests := [component_image.digest |
		some component in snapshot_components
		component_image := image.parse(component.containerImage)
	]

	some related_image in _related_images(input.image)
	not related_image.ref.digest in component_images_digests
]

# Extracts the related images attached to the image. The RELATED_IMAGES_DIGEST result
# contains the digest of a referring image manifest containing the related image json
# array. We need to find the blob sha in order to download the related images.
_related_images(tested_image) := [e |
	some imgs in [[r |
		input_image := image.parse(tested_image.ref)

		some related in lib.results_named(_related_images_result_name)
		result_digest := object.union(input_image, {"digest": sprintf("%s", [trim_space(related.value)])})
		related_image_ref := image.str(result_digest)
		related_image_manifest := ec.oci.image_manifest(related_image_ref)

		some layer in related_image_manifest.layers
		layer.mediaType == _related_images_oci_mime_type
		related_image_blob := object.union(input_image, {"digest": layer.digest})
		related_image_blob_ref := image.str(related_image_blob)

		raw_related_images := json.unmarshal(ec.oci.blob(related_image_blob_ref))

		some related_ref in raw_related_images
		r := {
			"path": "relatedImage",
			"ref": image.parse(related_ref),
		}
	]]
	some i in imgs

	e := {"ref": i.ref, "path": i.path}
]

# Finds all image references and their locations (paths). Returns all image
# references (parsed into components) found in locations as specified by:
# regal ignore:line-length
# https://github.com/containerbuildsystem/operator-manifest/blob/f24cd9374f5ad9fed04f47701acffa16837d940e/README.md#pull-specifications
# and https://osbs.readthedocs.io/en/latest/users.html#pullspec-locations
all_image_ref(manifest) := [e |
	# NOTE: use comprehensions in here, trying to set a value for `imgs` that
	# could be undefined will lead to the whole block being undefined, i.e.
	# don't do:
	# [
	#	{
	#      "path": "manifest.metadata.annotations.containerImage",
	#      "ref":image.parse(manifest.metadata.annotations.containerImage)
	#   }
	# ]
	# as the components of manifest.metadata.annotations.containerImage could be undefined!
	some imgs in [
		[r |
			# regal ignore:prefer-snake-case
			some i, related in manifest.spec.relatedImages
			r := {"path": sprintf("spec.relatedImages[%d].image", [i]), "ref": image.parse(related.image)}
		],
		[r |
			# regal ignore:prefer-snake-case
			manifest.metadata.annotations.containerImage
			r := {
				"path": "annotations.containerImage",
				"ref": image.parse(manifest.metadata.annotations.containerImage),
			}
		],
		[r |
			some _, values in walk(manifest)
			some key, val in values.metadata.annotations
			some annotation in regex.split(`(,|;|\n|\s+)`, val)
			ref := image.parse(trim_space(annotation))
			ref.repo # ones that are parsed as image reference, detected by having "repo" property set
			r := {"path": sprintf("annotations[%q]", [key]), "ref": ref}
		],
		[r |
			some d, deployment in manifest.spec.install.spec.deployments
			some c, container in deployment.spec.template.spec.containers
			ref := image.parse(container.image)
			r := {
				"path": sprintf(
					"spec.install.spec.deployments[%d (%q)].spec.template.spec.containers[%d (%q)].image",
					[d, _name(deployment), c, _name(container)],
				),
				"ref": ref,
			}
		],
		[r |
			some d, deployment in manifest.spec.install.spec.deployments

			# regal ignore:prefer-snake-case
			some c, initContainer in deployment.spec.template.spec.initContainers
			ref := image.parse(initContainer.image)
			r := {
				"path": sprintf(
					"spec.install.spec.deployments[%d (%q)].spec.template.spec.initContainers[%d (%q)].image",
					[d, _name(deployment), c, _name(initContainer)],
				),
				"ref": ref,
			}
		],
		[r |
			some d, deployment in manifest.spec.install.spec.deployments
			some c, container in deployment.spec.template.spec.containers
			some e in container.env
			startswith(e.name, "RELATED_IMAGE_")
			ref := image.parse(e.value)
			r := {
				"path": sprintf(
					"spec.install.spec.deployments[%d (%q)].spec.template.spec.containers[%d (%q)].env[%q]",
					[d, _name(deployment), c, _name(container), e.name],
				),
				"ref": ref,
			}
		],
		[r |
			some d, deployment in manifest.spec.install.spec.deployments

			# regal ignore:prefer-snake-case
			some c, initContainer in deployment.spec.template.spec.initContainers
			some e in initContainer.env
			startswith(e.name, "RELATED_IMAGE_")
			ref := image.parse(e.value)
			r := {
				"path": sprintf(
					"spec.install.spec.deployments[%d (%q)].spec.template.spec.initContainers[%d (%q)].env[%q]",
					[d, _name(deployment), c, _name(initContainer), e.name],
				),
				"ref": ref,
			}
		],
	]
	some i in imgs

	e := {"ref": i.ref, "path": i.path}
]

# Returns the ClusterServiceVersion manifests found in the OLM bundle.
_csv_manifests contains manifest if {
	manifest_dir := input.image.config.Labels[manifestv1]

	some path, manifest in input.image.files

	# only consider files in the manifest path as determined by the OLM manifest v1 label
	startswith(path, manifest_dir)

	# only consider this API prefix, disregard the version
	# regal ignore:prefer-snake-case
	startswith(manifest.apiVersion, "operators.coreos.com/")

	# only consider CSV manifests
	manifest.kind == "ClusterServiceVersion"
}

manifestv1 := "operators.operatorframework.io.bundle.manifests.v1"

_related_images_result_name := "RELATED_IMAGES_DIGEST"

_related_images_oci_mime_type := "application/vnd.konflux-ci.attached-artifact.related-images+json"

# Helper function to get the correctly formatted image reference string
_image_ref(unmatched_image) := ref if {
	# Case 1: Prioritize digest if present
	unmatched_image.digest != ""
	ref := sprintf("%s@%s", [unmatched_image.repo, unmatched_image.digest])
}

_image_ref(unmatched_image) := ref if {
	# Case 2: If no digest, but a tag is present
	unmatched_image.digest == ""
	unmatched_image.tag != ""
	ref := sprintf("%s:%s", [unmatched_image.repo, unmatched_image.tag])
}

_image_ref(unmatched_image) := ref if {
	# Case 3: Fallback if neither digest nor tag is present (only repo)
	# This ensures that image_ref is *always* defined if repo exists
	unmatched_image.digest == ""
	unmatched_image.tag == ""
	ref := unmatched_image.repo
}

_name(o) := n if {
	n := o.name
} else := "unnamed"
