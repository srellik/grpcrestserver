package(default_visibility = ["//visibility:public"])

load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "loginservice",
    srcs = ["login_service.go"],
    deps = [
        "//login_service/proto:login_service_go_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@org_golang_x_net//context:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
        "@org_golang_google_grpc//status:go_default_library",
        "@org_golang_google_grpc//codes:go_default_library",
        "@org_golang_google_grpc//metadata:go_default_library",
        "@com_github_dgrijalva_jwt_go//:go_default_library",
    ],
)
