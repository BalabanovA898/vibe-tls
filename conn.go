package vibe_tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const MaxPlaintextSize = 128

type Config struct {
	PrivateKey *rsa.PrivateKey
	Cert       []byte
	CAPubKey   *rsa.PublicKey
}

type SecureConn struct {
	net.Conn
	RemotePubKey *rsa.PublicKey
	Config       Config
}

type Certificate struct {
	Owner     string `json:"owner"`
	PublicKey []byte `json:"pub_key"`
	Signature []byte `json:"signature"`
}

func Dial(network, addr string, conf Config) (*SecureConn, error) {
	rawConn, _ := net.Dial(network, addr)
	sConn := &SecureConn{Conn: rawConn, Config: conf}

	if err := sConn.handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}

	return sConn, nil
}

func sendFramed(conn net.Conn, data []byte) error {
	length := uint32(len(data))
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, length)

	if _, err := conn.Write(header); err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	return nil
}

func receiveFramed(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(header)

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (s *SecureConn) Write(b []byte) (n int, err error) {
	totalLen := len(b)
	numChunks := (totalLen + MaxPlaintextSize - 1) / MaxPlaintextSize

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(numChunks))
	if _, err := s.Conn.Write(header); err != nil {
		return 0, err
	}

	for i := 0; i < totalLen; i += MaxPlaintextSize {
		end := i + MaxPlaintextSize

		end = min(end, totalLen)

		chunk := b[i:end]

		encryptedChunk, err := rsa.EncryptOAEP(
			sha256.New(),
			rand.Reader,
			s.RemotePubKey,
			chunk,
			nil,
		)
		if err != nil {
			return 0, fmt.Errorf("encryption failed: %v", err)
		}

		if err := sendFramed(s.Conn, encryptedChunk); err != nil {
			return 0, err
		}
	}

	return totalLen, nil
}

func (s *SecureConn) Read(b []byte) (n int, err error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(s.Conn, header); err != nil {
		return 0, err
	}
	numChunks := int(binary.BigEndian.Uint32(header))

	fullMessage := []byte{}

	for i := 0; i < numChunks; i++ {
		encryptedChunk, err := receiveFramed(s.Conn)
		if err != nil {
			return 0, err
		}

		decryptedChunk, err := rsa.DecryptOAEP(
			sha256.New(),
			rand.Reader,
			s.Config.PrivateKey,
			encryptedChunk,
			nil,
		)
		if err != nil {
			return 0, fmt.Errorf("decryption failed: %v", err)
		}

		fullMessage = append(fullMessage, decryptedChunk...)
	}

	copy(b, fullMessage)
	return len(fullMessage), nil
}
