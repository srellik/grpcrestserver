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
	HMACSecret = []byte("71eec4de2f7ea12a6533ff4abaf20e63a001b3a9")
)

type BearerToken string

type Credentials struct {
	UserId   string
	Password string
	Metadata []byte
}

type VerifyCredentialsFunc func(Credentials) (bool, []byte, error)
type GenerateTokenFunc func(Credentials, []byte) (BearerToken, error)
type ParseTokenFunc func(BearerToken) (Credentials, error)

type ServiceImpl struct {
	VerifyCredentialsFunc VerifyCredentialsFunc
	GenerateTokenFunc     GenerateTokenFunc
	ParseTokenFunc        ParseTokenFunc
}

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

func DefaultVerifyCredentialsFunc(c Credentials) (bool, []byte, error) {
	log.Print("Please replace DefaultVerifyCredentialsFunc, it's just returns true for all the requests.")
	return true, nil, nil
}

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
