package vibe_tls

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

func (s *SecureConn) handshake() error {
	if err := sendFramed(s.Conn, s.Config.Cert); err != nil {
		return fmt.Errorf("failed to send certificate: %v", err)
	}

	remoteCertData, err := receiveFramed(s.Conn)
	if err != nil {
		return fmt.Errorf("failed to receive remote certificate: %v", err)
	}

	var remoteCert Certificate
	if err := json.Unmarshal(remoteCertData, &remoteCert); err != nil {
		return fmt.Errorf("failed to parse remote certificate: %v", err)
	}

	signature := remoteCert.Signature
	remoteCert.Signature = nil
	dataToCheck, _ := json.Marshal(remoteCert)

	hash := sha256.Sum256(dataToCheck)
	err = rsa.VerifyPKCS1v15(s.Config.CAPubKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("INTRUDER ALERT! Certificate signature is invalid: %v", err)
	}

	block, _ := pem.Decode(remoteCert.PublicKey)
	if block == nil {
		return fmt.Errorf("failed to decode remote public key PEM")
	}
	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse remote public key: %v", err)
	}

	s.RemotePubKey = pubKey

	return nil
}
