// Private loopback-to-Unix relay. Run only inside the CLI network namespace.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

func relay(client net.Conn) {
	defer client.Close()
	gateway, err := net.DialTimeout("unix", "/gateway", 3*time.Second)
	if err != nil {
		return
	}
	defer gateway.Close()
	deadline := time.Now().Add(30 * time.Second)
	client.SetDeadline(deadline)
	gateway.SetDeadline(deadline)
	var copies sync.WaitGroup
	copies.Add(2)
	go func() {
		defer copies.Done()
		io.Copy(gateway, client)
		gateway.(*net.UnixConn).CloseWrite()
	}()
	io.Copy(client, gateway)
	client.(*net.TCPConn).CloseWrite()
	copies.Done()
	copies.Wait()
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
					relay(client)
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
