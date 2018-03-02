package(default_visibility = ["//visibility:public"])

load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

proto_library(
    name = "login_service_proto",
    srcs = ["login_service.proto"],
    deps = ["@com_github_googleapis_googleapis//:well_known_protos_proto"],
)

go_proto_library(
    name = "well_known_api_go_proto",
    importpath = "google/api",
    proto = "@com_github_googleapis_googleapis//:well_known_protos_proto",
    deps = [
        "@com_github_golang_protobuf//protoc-gen-go/descriptor:go_default_library",
    ],
)

go_proto_library(
    name = "login_service_go_proto",
    compilers = [
        "@io_bazel_rules_go//proto:go_grpc",
        "@io_bazel_rules_go//proto:go_grpc_gateway",
    ],
    importpath = "grpcrestserver/login_service/proto/login_service",
    proto = ":login_service_proto",
    deps = [
        ":well_known_api_go_proto",
    ],
)
