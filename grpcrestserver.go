// Package grpcrestserver serves the grpc and grpc-gateway rest handlers.
// This server extracts out all the boilerpalte code of creating a grpc/grpc-gateway server.
package grpcrestserver

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"

	"grpcrestserver/login_service/loginservice"
	lpb "grpcrestserver/login_service/proto/login_service"
)

// GRPCHandlerCallback is a callback which will be called while it is creating GRPC server,
// this handler must be responsible for initializing the service implementations.
type GRPCHandlerCallback func(*grpc.Server)

// RESTHandlerCallback is a callback which will be called while it is creating REST server,
// this handler must be responsible for initializing the service implementations.
type RESTHandlerCallback func(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error

// TLSOptions to connect securely between grpc server and grpc gateway.
type TLSOptions struct {
	// Path to Certificate file
	CertFilePath string
	// Path to the Key file
	KeyFilePath string
}

type AuthHelperFuncs struct {
	VerifyCredentialsFunc loginservice.VerifyCredentialsFunc
	GenerateTokenFunc     loginservice.GenerateTokenFunc
	ParseTokenFunc        loginservice.ParseTokenFunc
}

// Options to start the both grpc server and grpc-gateway server.
type Options struct {
	// GRPC server address eg. localhost:8889
	GRPCServerAddr string
	// REST server address eg. localhost:8888
	RESTServerAddr string
	// GRPC service handler callbacks
	GRPCServiceHandlers []GRPCHandlerCallback
	// REST endpoing handler callbacks
	RESTEndpointHandlers []RESTHandlerCallback
	// TLSOptions
	TLSOptions TLSOptions
	// AuthHelperFuncs which are used for login, authenticating each request.
	// These handlers are used at GRPC level.
	AuthHelperFuncs AuthHelperFuncs
	// Swagger json file paths
	SwaggerJsonFilePaths []string
}

// RunWith starts both GRPC server and REST server with the given options.
func RunWith(opts Options) {
	var (
		crtFile = opts.TLSOptions.CertFilePath
		keyFile = opts.TLSOptions.KeyFilePath
	)
	if !exists(crtFile) || !exists(keyFile) {
		crtFile = ""
		keyFile = ""
		log.Println("Certi and/or key files empty or doesn't exists, so will be running insecure GRPC server.")
	}

	go func() {
		if err := startGRPCServer(opts, crtFile, keyFile); err != nil {
			log.Fatalf("unable to start grpc server due to error: %v", err)
		}
	}()

	go func() {
		if err := startRESTServer(opts, crtFile); err != nil {
			log.Fatalf("unable to start rest server due to error: %v", err)
		}
	}()

	select {}
}

func startGRPCServer(o Options, crtFile, keyFile string) error {
	ls, err := net.Listen("tcp", o.GRPCServerAddr)
	if err != nil {
		return err
	}

	sOpts := []grpc.ServerOption{}

	if crtFile != "" && keyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(crtFile, keyFile)
		if err != nil {
			return err
		}
		sOpts = append(sOpts, grpc.Creds(creds))
	}

	sOpts = append(sOpts, grpc.UnaryInterceptor(authInterceptor(o.GRPCServerAddr, crtFile)))
	s := grpc.NewServer(sOpts...)

	vf := o.AuthHelperFuncs.VerifyCredentialsFunc
	gf := o.AuthHelperFuncs.GenerateTokenFunc
	tf := o.AuthHelperFuncs.ParseTokenFunc

	lpb.RegisterLoginServiceServer(s, loginservice.New(vf, gf, tf))

	for _, handler := range o.GRPCServiceHandlers {
		handler(s)
	}

	reflection.Register(s)
	return s.Serve(ls)
}

func startRESTServer(o Options, crtFile string) error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := http.NewServeMux()
	// Only add swagger endpoint if there are any swagger files available.
	if len(o.SwaggerJsonFilePaths) != 0 {
		mux.HandleFunc("/swagger/", swaggerServeHandler(o.SwaggerJsonFilePaths))
	}

	dialOpts := []grpc.DialOption{}
	if crtFile != "" {
		creds, err := credentials.NewClientTLSFromFile(crtFile, "")
		if err != nil {
			return fmt.Errorf("could not load TLS certificate: %s", err)
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
	} else {
		dialOpts = append(dialOpts, grpc.WithInsecure())
	}

	gw := runtime.NewServeMux()

	if err := lpb.RegisterLoginServiceHandlerFromEndpoint(ctx, gw, o.GRPCServerAddr, dialOpts); err != nil {
		return err
	}
	for _, handler := range o.RESTEndpointHandlers {
		if err := handler(ctx, gw, o.GRPCServerAddr, dialOpts); err != nil {
			return err
		}
	}

	mux.Handle("/", gw)
	log.Printf("starting REST server: %s", o.RESTServerAddr)
	return http.ListenAndServe(o.RESTServerAddr, mux)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func swaggerServeHandler(swaggerJsonFilePaths []string) func(http.ResponseWriter, *http.Request) {
	log.Printf("Serving swaggerJsonFilePaths %v", swaggerJsonFilePaths)
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Serving %s", r.URL.Path)
		p := strings.TrimPrefix(r.URL.Path, "/swagger/")
		if p == "" {
			http.NotFound(w, r)
			return
		}
		var swaggerToServe string
		for _, f := range swaggerJsonFilePaths {
			if strings.HasSuffix(p, f) {
				swaggerToServe = f
				break
			}
		}
		if swaggerToServe == "" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, swaggerToServe)
	}
}

var authPrefix = []string{"basic", "bearer"}
var skipAuth = map[string]bool{
	"/login_service.LoginService/Login":        true,
	"/login_service.LoginService/Authenticate": true,
}

func authInterceptor(grpcServerAddr, crtFile string) func(context.Context, interface{}, *grpc.UnaryServerInfo, grpc.UnaryHandler) (interface{}, error) {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skipping these RPC methods from auth interceptor.
		if _, ok := skipAuth[info.FullMethod]; ok {
			return handler(ctx, req)
		}
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, grpc.Errorf(codes.Internal, "failed to parse metadata")
		}

		headers := md["authorization"]
		if len(headers) == 0 {
			return nil, grpc.Errorf(codes.Unauthenticated, "invalid authorization headers")
		}

		bt := func() string {
			for _, h := range headers {
				for _, prefix := range authPrefix {
					if strings.HasPrefix(strings.ToLower(h), strings.ToLower(prefix)) {
						return h
					}
				}
			}
			return ""
		}()

		splits := strings.SplitN(bt, " ", 2)
		if len(splits) != 2 {
			return nil, grpc.Errorf(codes.Unauthenticated, "invalid authorization headers")
		}
		creds, err := authenticateReq(ctx, grpcServerAddr, crtFile, splits[1])
		if err != nil {
			return nil, err
		}
		// Add the credentials to the context so that the RPC method can be able to use it for processing.
		ctx = context.WithValue(ctx, "creds", loginservice.Credentials{
			UserId:   creds.UserId,
			Password: creds.Password,
			Metadata: creds.Metadata,
		})
		return handler(ctx, req)
	}
}

func authenticateReq(ctx context.Context, grpcServerAddr, crtFile, token string) (*lpb.Credentials, error) {
	dialOpts := []grpc.DialOption{}
	if crtFile != "" {
		creds, err := credentials.NewClientTLSFromFile(crtFile, "")
		if err != nil {
			return nil, err
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
	} else {
		dialOpts = append(dialOpts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(grpcServerAddr, dialOpts...)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	c := lpb.NewLoginServiceClient(conn)
	return c.Authenticate(ctx, &lpb.AuthenticateReq{Token: token})
}
