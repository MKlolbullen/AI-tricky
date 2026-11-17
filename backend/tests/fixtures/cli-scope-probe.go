// Runs in the same network namespace and mount layout as ffuf.
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func check() error {
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Flags&net.FlagLoopback == 0 {
		return fmt.Errorf("expected one loopback interface, found %v (%v)", interfaces, err)
	}
	if conn, err := net.DialTimeout("tcp4", os.Args[1], time.Second); err == nil {
		conn.Close()
		return fmt.Errorf("connected directly to host loopback")
	}
	if conn, err := net.DialTimeout("udp4", "192.0.2.1:53", time.Second); err == nil {
		conn.Close()
		return fmt.Errorf("opened a UDP socket with a route outside the namespace")
	}
	if _, err := os.Stat(os.Args[2]); !os.IsNotExist(err) {
		return fmt.Errorf("host file is visible: %v", err)
	}
	client := http.Client{Timeout: 3 * time.Second}
	for path, expected := range map[string]int{"/allowed": 200, "/blocked": 403} {
		response, err := client.Get("http://127.0.0.1:28080" + path)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != expected || (expected == 200 && string(body) != "fixture") {
			return fmt.Errorf("unexpected relay response: %v %q (%v)", response.StatusCode, body, err)
		}
	}
	return nil
}

func main() {
	if err := check(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
