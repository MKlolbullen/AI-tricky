// Private loopback-to-Unix relay. Run only inside the CLI network namespace.
//
// Plain requests are copied byte-for-byte to the gateway socket. A CONNECT is
// answered locally: the relay terminates TLS with a throwaway in-memory
// certificate and forwards each decrypted request to the gateway as an
// absolute https:// request line. The relay never dials a network address; the
// gateway outside the namespace authorizes and performs every real request,
// with certificate verification, through AI-tricky's scoped transport.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const gatewaySocket = "/gateway"

func dialGateway() (net.Conn, error) {
	return net.DialTimeout("unix", gatewaySocket, 3*time.Second)
}

// copyThrough keeps the original behaviour for non-CONNECT traffic.
func copyThrough(client net.Conn, buffered *bufio.Reader) {
	gateway, err := dialGateway()
	if err != nil {
		return
	}
	defer gateway.Close()
	gateway.SetDeadline(time.Now().Add(30 * time.Second))
	var copies sync.WaitGroup
	copies.Add(2)
	go func() {
		defer copies.Done()
		io.Copy(gateway, buffered)
		gateway.(*net.UnixConn).CloseWrite()
	}()
	io.Copy(client, gateway)
	client.(*net.TCPConn).CloseWrite()
	copies.Done()
	copies.Wait()
}

func refuse(conn net.Conn, status string) {
	fmt.Fprintf(conn, "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status)
}

// tunnel serves one CONNECT: local TLS termination, then one gateway
// round-trip per decrypted request. Only the method and target are forwarded.
func tunnel(client net.Conn, buffered *bufio.Reader, config *tls.Config) {
	request, err := http.ReadRequest(buffered)
	if err != nil || request.Method != http.MethodConnect || buffered.Buffered() != 0 {
		refuse(client, "400 Bad Request")
		return
	}
	authority := request.Host
	host, port, err := net.SplitHostPort(authority)
	if err != nil || host == "" || strings.ContainsAny(authority, " \t\r\n/@") {
		refuse(client, "400 Bad Request")
		return
	}
	if port == "443" {
		authority = host
		if strings.Contains(host, ":") {
			authority = "[" + host + "]"
		}
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	secure := tls.Server(client, config)
	defer secure.Close()
	if err := secure.Handshake(); err != nil {
		return
	}
	reader := bufio.NewReader(secure)
	for served := 0; served < 256; served++ {
		secure.SetDeadline(time.Now().Add(30 * time.Second))
		inner, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		io.Copy(io.Discard, io.LimitReader(inner.Body, 1<<20))
		inner.Body.Close()
		target := inner.URL.RequestURI()
		if !strings.HasPrefix(target, "/") || strings.ContainsAny(target, " \r\n") {
			refuse(secure, "400 Bad Request")
			return
		}
		gateway, err := dialGateway()
		if err != nil {
			refuse(secure, "502 Bad Gateway")
			return
		}
		gateway.SetDeadline(time.Now().Add(30 * time.Second))
		fmt.Fprintf(gateway, "%s https://%s%s HTTP/1.1\r\nHost: %s\r\n\r\n", inner.Method, authority, target, authority)
		response, err := http.ReadResponse(bufio.NewReader(gateway), inner)
		if err != nil {
			gateway.Close()
			refuse(secure, "502 Bad Gateway")
			return
		}
		response.Close = false
		response.Header.Del("Connection")
		err = response.Write(secure)
		response.Body.Close()
		gateway.Close()
		if err != nil || inner.Close {
			return
		}
	}
}

func relay(client net.Conn, config *tls.Config) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(30 * time.Second))
	buffered := bufio.NewReaderSize(client, 8192)
	first, err := buffered.Peek(8)
	if err == nil && string(first) == "CONNECT " {
		tunnel(client, buffered, config)
		return
	}
	copyThrough(client, buffered)
}

// throwaway creates a certificate that exists only in this process. Scanners in
// the namespace do not verify it; the real verification happens outside.
func throwaway() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ai-tricky-cli-relay"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}, nil
}

func run() error {
	listener, err := net.Listen("tcp4", "127.0.0.1:28080")
	if err != nil {
		return err
	}
	defer listener.Close()
	if len(os.Args) < 2 || os.Args[1] != "/scanner" {
		return fmt.Errorf("expected mounted scanner")
	}
	config, err := throwaway()
	if err != nil {
		return err
	}
	go func() {
		slots := make(chan struct{}, 16)
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
				go func() {
					defer func() { <-slots }()
					relay(client, config)
				}()
			default:
				client.Close()
			}
		}
	}()
	command := exec.Command(os.Args[1], os.Args[2:]...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "CLI scope relay:", err)
		if child, ok := err.(*exec.ExitError); ok && child.ExitCode() > 0 {
			os.Exit(child.ExitCode())
		}
		os.Exit(1)
	}
}
