// Command gozmq_sub checks the sequence published by satd's
// events/examples/zmtp_pub.rs with github.com/lightninglabs/gozmq, the ZMQ
// client LND uses for bitcoind's rawblock and rawtx notifications.
//
// Usage: gozmq_sub ENDPOINT [PREFIX...]
//
// With no PREFIX it subscribes to everything. It reads the messages whose
// topic matches a prefix, in order, compares each with the expected one,
// and exits 0 when all of them arrived intact.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lightninglabs/gozmq"
)

var (
	topics = []string{"hashblock", "hashtx", "rawblock", "rawtx", "sequence"}
	lens   = []int{0, 1, 32, 255, 256, 1000, 65535, 65536, 300000}
)

const (
	count   = 46
	lastLen = 4 << 20
)

func expected(i int) (string, []byte, []byte) {
	topic, n := topics[i%len(topics)], lens[i%len(lens)]
	if i+1 == count {
		topic, n = "rawblock", lastLen
	}
	body := make([]byte, n)
	for j := range body {
		body[j] = byte((i*7 + j) % 251)
	}
	seq := make([]byte, 4)
	binary.LittleEndian.PutUint32(seq, uint32(i))
	return topic, body, seq
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gozmq_sub ENDPOINT [PREFIX...]")
		os.Exit(2)
	}
	endpoint, prefixes := os.Args[1], os.Args[2:]
	if len(prefixes) == 0 {
		prefixes = []string{""}
	}
	conn, err := gozmq.Subscribe(endpoint, prefixes, 30*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gozmq: subscribe %s: %v\n", endpoint, err)
		os.Exit(1)
	}
	defer conn.Close()

	got, bodyBytes := 0, 0
	for i := 0; i < count; i++ {
		topic, body, seq := expected(i)
		match := false
		for _, p := range prefixes {
			if strings.HasPrefix(topic, p) {
				match = true
			}
		}
		if !match {
			continue
		}
		parts, err := conn.Receive(nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gozmq: message %d: %v\n", i, err)
			os.Exit(1)
		}
		if len(parts) != 3 || string(parts[0]) != topic || !bytes.Equal(parts[1], body) ||
			!bytes.Equal(parts[2], seq) {
			fmt.Fprintf(os.Stderr, "gozmq: message %d: got %d parts, topic %q, body %d bytes; "+
				"want topic %q, body %d bytes\n", i, len(parts), parts[0], len(parts[1]), topic, len(body))
			os.Exit(1)
		}
		got++
		bodyBytes += len(body)
	}
	fmt.Printf("gozmq: OK, %d messages, %d body bytes\n", got, bodyBytes)
}
