package(default_visibility = ["//visibility:public"])

load("@io_bazel_rules_go//go:def.bzl", "go_prefix")

go_prefix("grpcrestserver")

load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library")

go_library(
    name = "go_default_library",
    srcs = ["grpcrestserver.go"],
    importpath = "github.com/srellik/grpcrestserver",
    deps = [
        "//login_service:go_default_library",
        "//login_service/proto:login_service_go_proto",
        "@com_github_grpc_ecosystem_grpc_gateway//runtime:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
        "@org_golang_google_grpc//reflection:go_default_library",
        "@org_golang_google_grpc//credentials:go_default_library",
        "@org_golang_x_net//context:go_default_library",
        "@org_golang_google_grpc//codes:go_default_library",
        "@org_golang_google_grpc//metadata:go_default_library",
    ],
)
