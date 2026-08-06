// Command tls_tail tails the firehose over TLS, so the bearer token and the
// event stream are never sent in cleartext.
//
//	# Pin a satd node's own (self-signed) CA — the usual case:
//	go run ./tls_tail -endpoint node.example:50051 -ca ./node-ca.pem [-token TOKEN]
//
//	# Server with a publicly trusted certificate — omit -ca to use the system roots:
//	go run ./tls_tail -endpoint node.example:50051
//
// Note the endpoint must not be spelled `http://...`. The SDK refuses to
// connect when TLS is requested against an explicit plaintext scheme rather
// than silently downgrading — that combination can only be a mistake, and
// downgrading it would leak the token while the caller believed otherwise.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"

	satdevents "github.com/epochbtc/satd/clients/go"
)

func main() {
	endpoint := flag.String("endpoint", "127.0.0.1:50051", "satd gRPC endpoint")
	caPath := flag.String("ca", "", "PEM file of the server's CA; empty uses the system roots")
	serverName := flag.String("server-name", "", "override the SNI / certificate name to verify")
	token := flag.String("token", "", "bearer token, if the node requires one")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	opts := []satdevents.Option{satdevents.WithTLS()}
	if *caPath != "" {
		pem, err := os.ReadFile(*caPath)
		if err != nil {
			log.Fatalf("read CA: %v", err)
		}
		// Pins this CA INSTEAD of the system roots: a satd node's own
		// certificate is not signed by anything the system trusts.
		opts = append(opts, satdevents.WithTLSCAPem(pem))
	}
	if *serverName != "" {
		// Needed when dialing by IP, or through a tunnel whose address does not
		// match the name in the node's certificate.
		opts = append(opts, satdevents.WithTLSServerName(*serverName))
	}
	if *token != "" {
		opts = append(opts, satdevents.WithBearerToken(*token))
	}

	client, err := satdevents.Dial(ctx, *endpoint, opts...)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	stream, err := client.Subscribe(ctx, satdevents.SubscribeOptions{
		Categories: satdevents.CategoryMempool | satdevents.CategoryChain,
	})
	if err != nil {
		log.Fatalf("subscribe: %v", err)
	}

	for {
		ev, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return
			}
			log.Fatalf("recv: %v", err)
		}
		if e, ok := ev.(*satdevents.BlockConnected); ok {
			fmt.Printf("block %d %s\n", e.Height, satdevents.DisplayHex(e.Hash))
		} else {
			fmt.Printf("event %T\n", ev)
		}
	}
}
