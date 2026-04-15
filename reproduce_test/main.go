package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/source"
)

func main() {
	ms := source.NewMemorySource()
	if err := ms.LoadFile(os.Args[1]); err != nil {
		fmt.Println("LoadFile err:", err)
		return
	}

	// Same as cilock verify: load the public key as verifier.
	keyBytes, _ := os.ReadFile(os.Args[3])
	verifier, err := cryptoutil.NewVerifierFromReader(bytesReader(keyBytes))
	if err != nil {
		fmt.Println("verifier err:", err)
		return
	}
	vs := source.NewVerifiedSource(ms, dsse.VerifyWithVerifiers(verifier))

	fmt.Println("calling VerifiedSource.SearchByPredicateType with subject=", os.Args[2])
	results, err := vs.SearchByPredicateType(context.Background(),
		[]string{"https://slsa.dev/verification_summary/v1"},
		[]string{os.Args[2]},
	)
	fmt.Println("results:", len(results), "err:", err)
	for _, r := range results {
		fmt.Printf("  ref=%s verifiers=%d errors=%d\n", r.Reference, len(r.Verifiers), len(r.Errors))
		for _, e := range r.Errors {
			fmt.Println("    err:", e)
		}
	}
}

func bytesReader(b []byte) *bytesReaderT { return &bytesReaderT{b: b} }

type bytesReaderT struct {
	b   []byte
	pos int
}

func (b *bytesReaderT) Read(p []byte) (int, error) {
	if b.pos >= len(b.b) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, b.b[b.pos:])
	b.pos += n
	return n, nil
}
