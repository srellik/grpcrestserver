package loginservice

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	jwt "github.com/dgrijalva/jwt-go"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "grpcrestserver/login_service/proto/login_service"
)

var (
	// HAMCSecret used by the DefaultGenerateTokenFunc and DefaultParseTokenFunc functions for generating and parsing the token.
	HMACSecret = []byte("71eec4de2f7ea12a6533ff4abaf20e63a001b3a9")
)

// BearerToken is the token from HTTP Authorization header.
type BearerToken string

// Credentials is a container used to store or pass around the user credentials.
type Credentials struct {
	// UserId is the unique identifier of an user.
	UserId string
	// Password is the secret to identify the user.
	Password string
	// Metadata is the any applicaton specific extra data.
	// Most common use case is to put a encoded json message in Metadata.
	Metadata []byte
}

// VerifyCredentialsFunc is a handler to verify the client provided user credentials.
type VerifyCredentialsFunc func(Credentials) (bool, []byte, error)

// GenerateTokenFunc is a handler to generate a token based on the provided user credentials.
type GenerateTokenFunc func(Credentials, []byte) (BearerToken, error)

// ParseTokenFunc is a handler to parse the user provided BearerToken and return the Credentials.
type ParseTokenFunc func(BearerToken) (Credentials, error)

// ServiceImpl is an implementation of pb.LoginService
type ServiceImpl struct {
	VerifyCredentialsFunc VerifyCredentialsFunc
	GenerateTokenFunc     GenerateTokenFunc
	ParseTokenFunc        ParseTokenFunc
}

// New creates a new login service with provided handlers. If the nil handlers are given, they will be replaced with default handlers.
// When GenerateTokenFunc or ParseTokenFunc or one of them are nil, both the handlers will be replaces with default handlers.
// Do not forget to refer: DefaultVerifyCredentialsFunc, DefaultGenerateTokenFunc, DefaultParseTokenFunc.
func New(v VerifyCredentialsFunc, g GenerateTokenFunc, t ParseTokenFunc) *ServiceImpl {
	if v == nil {
		v = DefaultVerifyCredentialsFunc
	}
	// Generate token function and taken validation function will go as pair. We must find a betterway to allow developers to configure it.
	if g == nil || t == nil {
		g = DefaultGenerateTokenFunc
		t = DefaultParseTokenFunc
	}

	return &ServiceImpl{VerifyCredentialsFunc: v, GenerateTokenFunc: g, ParseTokenFunc: t}
}

// Login
//	Step 1: Calls VerifyCredentialsFunc, anything wrong, returns codes.NotFound error.
//	Step 2: Calls GenerateTokenFunc, anything wrong, return codes.Unauthenticated error.
//	Step 3: Reponds with token.
func (s *ServiceImpl) Login(ctx context.Context, in *pb.Credentials) (*pb.TokenResponse, error) {
	creds := Credentials{
		UserId:   in.UserId,
		Password: in.Password,
		Metadata: in.Metadata,
	}
	ok, extras, err := s.VerifyCredentialsFunc(creds)
	if !ok || err != nil {
		log.Printf("Error: %v", err)
		return nil, status.Error(codes.NotFound, fmt.Sprintf("failed to verify user %v", in.UserId))
	}
	token, err := s.GenerateTokenFunc(creds, extras)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("%v not allowed", in.UserId))
	}
	return &pb.TokenResponse{
		Token: string(token),
	}, nil
}

// Authenticate calls the ParseTokenFunc with token, if anything wrong return codes.Unauthenticated error.
func (s *ServiceImpl) Authenticate(ctx context.Context, in *pb.AuthenticateReq) (*pb.Credentials, error) {
	creds, err := s.ParseTokenFunc(BearerToken(in.Token))
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("invalid token %v", in.Token))
	}
	return &pb.Credentials{
		UserId:   creds.UserId,
		Password: creds.Password,
		Metadata: creds.Metadata,
	}, nil
}

// DefaultVerifyCredentialsFunc always return true, please replace this handler.
func DefaultVerifyCredentialsFunc(c Credentials) (bool, []byte, error) {
	log.Print("Please replace DefaultVerifyCredentialsFunc, it's just returns true for all the requests.")
	return true, nil, nil
}

// DefaultGenerateTokenFunc will generate a jwt based using HMACSecret, and it stores the provided Credentials as one of the claims with key as "creds".
// Note: This handler clears the password just to not to leak the sensitive information.
func DefaultGenerateTokenFunc(c Credentials, _ []byte) (BearerToken, error) {
	// Clear the password for the sake of privacy.
	c.Password = ""
	cJson, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	genTime := time.Now().UnixNano()
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"creds": string(cJson),
		"time":  genTime,
	})

	token, err := t.SignedString(HMACSecret)
	return BearerToken(token), err
}

// DefaultParseTokenFunc parses the jwt using HMACSecret and returns the stored Credentials in the jwt claims.
// It must be used only with DefaultGenerateTokenFunc.
func DefaultParseTokenFunc(bt BearerToken) (Credentials, error) {
	creds := Credentials{}
	t, err := jwt.Parse(string(bt), func(jt *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := jt.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", jt.Header["alg"])
		}
		return HMACSecret, nil
	})
	if err != nil {
		return creds, err
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok || !t.Valid {
		return creds, status.Error(codes.Internal, fmt.Sprintf("failed to parse token %v", bt))
	}
	if err := json.Unmarshal([]byte(claims["creds"].(string)), &creds); err != nil {
		return creds, status.Error(codes.Internal, fmt.Sprintf("failed to parse token %v", bt))
	}
	return creds, nil
}
