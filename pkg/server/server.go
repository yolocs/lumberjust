package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	cred "cloud.google.com/go/iam/credentials/apiv1"
	resourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	credpb "google.golang.org/genproto/googleapis/iam/credentials/v1"
	"google.golang.org/grpc/codes"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/golang-jwt/jwt"
	"github.com/yolocs/lumberjust/pkg/apis"
)

const (
	expireWindow = 10 & time.Minute
)

type justificationClaims struct {
	jwt.StandardClaims

	Justification string `json:"justification,omitempty"`
}

type Impl struct {
	apis.UnimplementedJustInTimeServer

	RMClient   *resourcemanager.Service
	CredClient *cred.IamCredentialsClient

	// https://stackoverflow.com/questions/65821436/programmatically-get-current-service-account-on-gcp
	ServiceAccount string
}

func (s *Impl) Justify(ctx context.Context, req *apis.JustificationRequest) (*apis.JustificationResponse, error) {
	log.Println("Received a request")

	identity, err := incomingIdentity(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "failed to retrieve identity: %v", err)
	}

	policy, err := s.RMClient.Projects.GetIamPolicy(req.Resource, &resourcemanager.GetIamPolicyRequest{
		Options: &resourcemanager.GetPolicyOptions{
			RequestedPolicyVersion: 3,
		},
	}).Do()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot retrieve existing project IAM policy: %v", err)
	}

	issueTime := time.Now()

	if policy.Bindings == nil {
		policy.Bindings = []*resourcemanager.Binding{}
	}
	policy.Bindings = append(policy.Bindings, &resourcemanager.Binding{
		Role:    req.Role,
		Members: []string{withMemberPrefix(identity)},
		Condition: &resourcemanager.Expr{
			Title:      "expire_in_ten_mins", // could be something more unique?
			Expression: expireExpr(issueTime),
		},
	})
	// It seems I have to set this value always.
	policy.Version = 3

	if _, err := s.RMClient.Projects.SetIamPolicy(req.Resource, &resourcemanager.SetIamPolicyRequest{
		Policy: policy,
	}).Do(); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to set project IAM policy: %v", err)
	}

	claims := justificationClaims{}
	claims.Audience = req.Audience
	// Cannot set issuer otherwise the request will be invalid.
	// claims.Issuer = s.ServiceAccount // should be the service account
	claims.IssuedAt = issueTime.Unix()
	claims.ExpiresAt = issueTime.Add(expireWindow).Unix()
	claims.NotBefore = issueTime.Unix()
	claims.Justification = fmt.Sprintf(`{"reason":%q,"ticket":%q}`, req.Reason, req.Ticket)

	jToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	claimsBytes, err := json.Marshal(jToken.Claims)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate justification token: %v", err)
	}

	log.Printf("Justification token to be signed: %s\n", string(claimsBytes))
	log.Printf("Signing token with service account %s\n", s.ServiceAccount)

	jTokenSigned, err := s.CredClient.SignJwt(ctx, &credpb.SignJwtRequest{
		Name:    fmt.Sprintf("projects/-/serviceAccounts/%s", s.ServiceAccount),
		Payload: string(claimsBytes),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign justification token: %v", err)
	}

	return &apis.JustificationResponse{
		Token: jTokenSigned.SignedJwt,
	}, nil
}

func expireExpr(issueTime time.Time) string {
	return fmt.Sprintf("request.time < timestamp('%s')", issueTime.Add(expireWindow).UTC().Format(time.RFC3339))
}

func withMemberPrefix(identity string) string {
	if strings.HasSuffix(identity, ".gserviceaccount.com") {
		return "serviceAccount:" + identity
	}
	return "user:" + identity
}

func incomingIdentity(ctx context.Context) (string, error) {
	md, ok := grpcmetadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("missing gRPC incoming context")
	}

	var idToken string
	if len(md["authorization"]) > 0 {
		idToken = strings.TrimPrefix(md["authorization"][0], "Bearer ")
	}

	// Retrieve the identity
	// log.Printf("Received idToken: %s\n", idToken)
	p := &jwt.Parser{}
	claims := jwt.MapClaims{}
	_, _, err := p.ParseUnverified(idToken, claims)
	if err != nil {
		return "", fmt.Errorf("invalid auth token: %w", err)
	}

	identity := claims["email"].(string)
	if identity == "" {
		return "", fmt.Errorf("missing identity")
	}

	return identity, nil
}
