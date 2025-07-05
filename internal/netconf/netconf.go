package netconf

import (
	"context"
	"log"
	"time"

	"github.com/nemith/netconf"
	ncssh "github.com/nemith/netconf/transport/ssh"
	"golang.org/x/crypto/ssh"

)

func connect(ctx context.Context) (*netconf.Session, error) {
	sshServer := "172.0.13.2:22"
	sshConfig := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{
			ssh.Password("Password1"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	transport, err := ncssh.Dial(ctx, "tcp", sshServer, sshConfig)
	if err != nil {
		return nil, err
	}
	defer transport.Close()

	session, err := netconf.Open(transport)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func GetConfig() {
	sshCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	session, err := connect(sshCtx)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close(context.Background())

	log.Printf("Client Capabilities: %s", session.ServerCapabilities())
	deviceConfig, err := session.GetConfig(context.Background(), netconf.Datastore(netconf.Running))
	if err != nil {
		log.Fatalf("failed to get config: %v", err)
	}

	log.Printf("Device Config: %s", deviceConfig)
}

func Example_ssh() {
	sshServer := "172.0.13.2:22"
	sshConfig := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{
			ssh.Password("Password1"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	transport, err := ncssh.Dial(ctx, "tcp", sshServer,  sshConfig)
	if err != nil {
		panic(err)
	}
	defer transport.Close()

	session, err := netconf.Open(transport)
	if err != nil {
		panic(err)
	}

	// timeout for the call itself.
	ctx, cancel = context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	deviceConfig, err := session.GetConfig(ctx, "running")
	if err != nil {
		log.Fatalf("failed to get config: %v", err)
	}

	log.Printf("Config:\n%s\n", deviceConfig)

	if err := session.Close(context.Background()); err != nil {
		log.Print(err)
	}
}