package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/crypto/ssh"
)

// zeroSource is an io.Reader that returns an unlimited number of zero bytes.
type zeroSource struct{}

func (zeroSource) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

func getSigner() ssh.Signer {
	var pkeyfile string
	if runtime.GOOS == "windows" {
		pkeyfile = filepath.Join(os.Getenv("USERPROFILE"), ".ssh", "id_rsa")
	} else {
		pkeyfile = filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa")
	}
	key, err := os.ReadFile(pkeyfile)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
	}
	return signer
}

func main() {
	//var hostKey ssh.PublicKey
	// An SSH client is represented with a ClientConn.
	//
	// To authenticate with the remote server you must pass at least one
	// implementation of AuthMethod via the Auth field in ClientConfig,
	// and provide a HostKeyCallback.
	config := &ssh.ClientConfig{
		Config: ssh.Config{
			Rand: zeroSource{},
		},
		User: os.Getenv("user"),
		Auth: []ssh.AuthMethod{
			// ssh.PublicKeys(getSigner()),
			ssh.Password(os.Getenv("password")),
		},
		//HostKeyCallback: ssh.FixedHostKey(hostKey),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", os.Getenv("ip"), config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	defer client.Close()

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}
	defer session.Close()

	// Once a Session is created, you can execute a single command on
	// the remote side using the Run method.
	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run("/usr/bin/whoami"); err != nil {
		log.Fatal("Failed to run: " + err.Error())
	}
	fmt.Print(b.String())
}
