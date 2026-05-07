package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

type Certificate struct {
	Owner     string `json:"owner"`
	PublicKey []byte `json:"pub_key"`
	Signature []byte `json:"signature"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: custom-ca <command> [options]")
		return
	}

	switch os.Args[1] {
	case "key-gen":
		keyGen(os.Args[2:])
	case "cert-gen":
		certGen(os.Args[2:])
	default:
		fmt.Println("Unknown command")
	}
}

func keyGen(args []string) {
	fs := flag.NewFlagSet("key-gen", flag.ExitOnError)
	name := fs.String("name", "service", "Name of the key owner")
	fs.Parse(args)

	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	privBytes := x509.MarshalPKCS1PrivateKey(key)
	savePEM(fmt.Sprintf("%s.key", *name), "RSA PRIVATE KEY", privBytes)

	pubBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	savePEM(fmt.Sprintf("%s.pub", *name), "RSA PUBLIC KEY", pubBytes)

	fmt.Printf("Generated keys for: %s\n", *name)
}

func certGen(args []string) {
	fs := flag.NewFlagSet("cert-gen", flag.ExitOnError)
	pubFile := fs.String("pub", "", "Public key to sign")
	caKeyFile := fs.String("ca-key", "ca.key", "CA private key")
	owner := fs.String("owner", "owner", "Owner name in cert")
	fs.Parse(args)

	pubBytes, _ := os.ReadFile(*pubFile)

	caKeyBytes, _ := os.ReadFile(*caKeyFile)
	block, _ := pem.Decode(caKeyBytes)
	caPriv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	cert := Certificate{
		Owner:     *owner,
		PublicKey: pubBytes,
	}

	dataToSign, _ := json.Marshal(cert)
	hash := sha256.Sum256(dataToSign)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, caPriv, crypto.SHA256, hash[:])

	cert.Signature = signature

	finalCert, _ := json.MarshalIndent(cert, "", "  ")
	os.WriteFile(fmt.Sprintf("%s.cert", *owner), finalCert, 0644)
	fmt.Println("Certificate generated!")
}

func savePEM(filename, typeLabel string, bytes []byte) {
	f, _ := os.Create(filename)
	pem.Encode(f, &pem.Block{Type: typeLabel, Bytes: bytes})
}
