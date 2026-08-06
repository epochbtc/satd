// Command mtls_tail tails the firehose over mutual TLS — it presents a client
// certificate to a satd node configured with `eventsgrpcmtls=1`. The node
// verifies the client certificate against its configured CA (and any CN /
// DNS-SAN allowlist); this client pins the node's CA in turn.
//
//	go run ./mtls_tail -endpoint node.example:50051 \
//	    -ca ./node-ca.pem -cert ./client-cert.pem -key ./client-key.pem
//
// Pinning the server CA is required for the usual self-signed satd node:
// without -ca the SERVER's certificate is checked against the system roots and
// the handshake fails before the client certificate is ever presented.
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
	caPath := flag.String("ca", "", "PEM file of the server's CA (required for a self-signed node)")
	certPath := flag.String("cert", "", "client certificate PEM (required)")
	keyPath := flag.String("key", "", "client private key PEM (required)")
	flag.Parse()

	if *certPath == "" || *keyPath == "" {
		log.Fatal("-cert and -key are required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cert, err := os.ReadFile(*certPath)
	if err != nil {
		log.Fatalf("read client cert: %v", err)
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatalf("read client key: %v", err)
	}

	// WithMTLS implies TLS; it adds the client identity to it.
	opts := []satdevents.Option{satdevents.WithMTLS(cert, key)}
	if *caPath != "" {
		ca, err := os.ReadFile(*caPath)
		if err != nil {
			log.Fatalf("read CA: %v", err)
		}
		opts = append(opts, satdevents.WithTLSCAPem(ca))
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
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
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
