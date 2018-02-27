workspace(name = "srellik_grpcrestserver")

# Go rules for Bazel.
git_repository(
    name = "io_bazel_rules_go",
    commit = "b5b3644b8508360ad2c85bb10b277e712004650d",
    remote = "https://github.com/chaitanya9186/rules_go.git",
)

load("@io_bazel_rules_go//go:def.bzl", "go_rules_dependencies", "go_register_toolchains")

go_rules_dependencies()

go_register_toolchains()

GOOGLEAPIS_BUILD_FILE = """
package(default_visibility = ["//visibility:public"])

exports_files(
    [
        "google/api/http.proto",
        "google/api/annotations.proto",
    ],
    visibility = ["//visibility:public"],
)

WELL_KNOWN_PROTOS = [
    "google/api/http.proto",
    "google/api/annotations.proto",
]

filegroup(name="well_known_protos", srcs=WELL_KNOWN_PROTOS,)
filegroup(name="annotations_proto", srcs=["google/api/annotations.proto"],)

proto_library(
    name = "well_known_protos_proto",
    srcs = WELL_KNOWN_PROTOS,
    visibility = ["//visibility:public"],
    deps = ["@com_google_protobuf//:descriptor_proto"],
)
"""

new_git_repository(
    name = "com_github_googleapis_googleapis",
    build_file_content = GOOGLEAPIS_BUILD_FILE,
    remote = "https://github.com/googleapis/googleapis.git",
    tag = "common-protos-1_3_1",
)

## For generating swagger file.
git_repository(
    name = "org_pubref_rules_protobuf",
    #tag = "v0.7.2",
    commit = "563b674a2ce6650d459732932ea2bc98c9c9a9bf",  # alternatively, use latest commit on master
    remote = "https://github.com/pubref/rules_protobuf",
)

load("@org_pubref_rules_protobuf//go:rules.bzl", "go_proto_repositories")

go_proto_repositories(excludes = [
    "com_google_protobuf",
    "org_golang_google_grpc",
])

load("@org_pubref_rules_protobuf//grpc_gateway:rules.bzl", "grpc_gateway_proto_repositories")

grpc_gateway_proto_repositories(excludes = [
    "com_google_protobuf",
    "org_golang_google_grpc",
])

git_repository(
    name = "io_bazel_rules_docker",
    commit = "0d6b0a387b1a04e3b987f9761d21a41b1edc8039",
    remote = "https://github.com/bazelbuild/rules_docker.git",
    #tag = "v0.3.0",
)

load(
    "@io_bazel_rules_docker//container:container.bzl",
    "container_pull",
    _container_repositories = "repositories",
)

_container_repositories()

load(
    "@io_bazel_rules_docker//go:image.bzl",
    _go_image_repos = "repositories",
)

_go_image_repos()
