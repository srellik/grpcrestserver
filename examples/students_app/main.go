package main

import (
	"context"
	"math/rand"
	"time"

	"grpcrestserver"
	"grpcrestserver/examples/students_app/service_impl/studentsservice"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"google.golang.org/grpc"

	sspb "grpcrestserver/examples/students_app/proto/students_service"
)

func main() {
	opts := grpcrestserver.Options{
		GRPCServerAddr: "localhost:8889",
		RESTServerAddr: ":8888",
		GRPCServiceHandlers: []grpcrestserver.GRPCHandlerCallback{
			func(s *grpc.Server) {
				sspb.RegisterStudentsServiceServer(s, &studentsservice.StudentsRPCServiceImpl{
					R: rand.New(rand.NewSource(time.Now().Unix())),
				})
			},
		},
		RESTEndpointHandlers: []grpcrestserver.RESTHandlerCallback{
			func(ctx context.Context, gw *runtime.ServeMux, grpcServerAddr string, dialOpts []grpc.DialOption) error {
				return sspb.RegisterStudentsServiceHandlerFromEndpoint(ctx, gw, grpcServerAddr, dialOpts)
			},
		},
	}
	grpcrestserver.RunWith(opts)
}

func isTokenValidFunc()
