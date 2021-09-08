package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/google/shlex"
	"github.com/yolocs/lumberjust/pkg/apis"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

var (
	user     = flag.String("as", "", "Start session as the given service account; the principle must have permission to impersonate the SA")
	server   = flag.String("server", "lumberjust-r7y74tbhjq-uc.a.run.app", "The lumberjust server")
	audience = flag.String("audience", "", "The service you want to talk to")
	resource = flag.String("resource", "", "The GCP resource to require access to (only project is supported)")
	role     = flag.String("role", "", "The IAM role to require to access the resource")
	reason   = flag.String("reason", "", "The reason to access the service/resource")
	ticket   = flag.String("ticket", "", "The link to a ticket (not really useful today)")
)

func main() {
	flag.Parse()
	if *audience == "" || *resource == "" || *role == "" || *reason == "" {
		log.Fatal("audience/resource/role/reason must all be set")
	}

	ctx := context.Background()
	if err := doMain(ctx); err != nil {
		log.Fatal(err)
	}
}

func doMain(ctx context.Context) error {
	conn, err := connLumberjust()
	if err != nil {
		return err
	}
	defer conn.Close()
	client := apis.NewJustInTimeClient(conn)
	jToken, err := genJToken(ctx, client)
	if err != nil {
		return err
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		cmdString, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}

		args, err := shlex.Split(strings.TrimSuffix(cmdString, "\n"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		switch args[0] {
		case "exit":
			os.Exit(0)
		case "grpc_cli":
			if err := runGRPC(args, jToken); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}
	}
}

func runGRPC(args []string, jToken string) error {
	idToken, err := genIDToken(*audience)
	if err != nil {
		return err
	}

	args = append(args, "--channel_creds_type=ssl")
	args = append(args, fmt.Sprintf(`--call_creds=access_token=%s`, idToken))
	args = append(args, fmt.Sprintf(`--metadata=justification:%s`, jToken))

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout

	// log.Printf("Running GRPC: %v\n", cmd.String())

	return cmd.Run()
}

func connLumberjust() (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		grpc.WithAuthority(fmt.Sprintf("%s:443", *server)),
		grpc.WithBlock(),
	}

	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	cred := credentials.NewTLS(&tls.Config{
		RootCAs: systemRoots,
	})
	opts = append(opts, grpc.WithTransportCredentials(cred))

	return grpc.Dial(fmt.Sprintf("%s:443", *server), opts...)
}

func genJToken(ctx context.Context, client apis.JustInTimeClient) (string, error) {
	token, err := genIDToken("https://" + *server)
	if err != nil {
		return "", err
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	resp, err := client.Justify(ctx, &apis.JustificationRequest{
		Audience: *audience,
		Resource: *resource,
		Role:     *role,
		Reason:   *reason,
		Ticket:   *ticket,
	})
	if err != nil {
		return "", err
	}
	return resp.Token, nil
}

func genIDToken(audience string) (string, error) {
	var cmd *exec.Cmd
	if *user == "" {
		cmd = exec.Command("gcloud", "auth", "print-identity-token", fmt.Sprintf(`--audiences=%s`, audience))
	} else {
		cmd = exec.Command("gcloud", "auth", "print-identity-token", fmt.Sprintf(`--audiences=%s`, audience), fmt.Sprintf("--impersonate-service-account=%s", *user), "--include-email")
	}

	var buf strings.Builder
	cmd.Stdout = &buf

	// log.Printf("Running command: %v\n", cmd.String())

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to generate id token: %w", err)
	}

	// log.Printf("Got token: %s\n", buf.String())

	return strings.Trim(buf.String(), "\n "), nil
}
