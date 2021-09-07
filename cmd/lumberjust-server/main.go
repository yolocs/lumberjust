package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"cloud.google.com/go/compute/metadata"
	cred "cloud.google.com/go/iam/credentials/apiv1"
	resourcemanager "google.golang.org/api/cloudresourcemanager/v1"

	pb "github.com/yolocs/lumberjust/pkg/apis"
	"github.com/yolocs/lumberjust/pkg/server"
)

func main() {
	ctx := context.Background()

	account, err := metadata.Email("default")
	if err != nil {
		log.Fatalf("failed to query default service account email: %v", err)
	}

	rm, err := resourcemanager.NewService(ctx)
	if err != nil {
		log.Fatalf("failed to create resource manager client: %v", err)
	}

	creds, err := cred.NewIamCredentialsClient(ctx)
	if err != nil {
		log.Fatalf("failed to create IAM credentials client: %v", err)
	}

	server := &server.Impl{
		RMClient:       rm,
		CredClient:     creds,
		ServiceAccount: account,
	}

	lis, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterJustInTimeServer(s, server)
	reflection.Register(s)

	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
