// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/log"
)

func retainUnstoredEnvelope(path string, env dsse.Envelope) string {
	if path != "" {
		abs, err := filepath.Abs(path)
		if err != nil {
			return path
		}
		return abs
	}
	body, err := json.Marshal(env)
	if err != nil {
		log.Errorf("could not keep the unstored signed envelope: %v", err)
		return ""
	}
	dir, err := newRunEvidenceDir()
	if err != nil {
		log.Errorf("could not keep the unstored signed envelope: %v", err)
		return ""
	}
	kept := filepath.Join(dir, "attestation.json")
	if err := writePrivateRunEnvelope(kept, body); err != nil {
		log.Errorf("could not keep the unstored signed envelope: %v", err)
		return ""
	}
	return kept
}

func retainedEvidenceError(cause error, kept, archivistaURL string) error {
	if kept == "" {
		return fmt.Errorf("%w\n  the signed envelope could NOT be kept on disk and was only written to stdout; capture it or re-run `cilock run`", cause)
	}
	if _, err := os.Stat(kept); err != nil {
		return fmt.Errorf("%w\n  the signed envelope was meant to be at %s but that path is unreadable (%v); re-run `cilock run`", cause, kept, err)
	}
	upload := "upload it later with a valid bearer token: curl --fail-with-body -X POST -H 'Content-Type: application/json' " +
		"-H \"Authorization: Bearer $TOKEN\" --data-binary @" + shellQuote(kept) + " " + shellQuote(strings.TrimRight(archivistaURL, "/")+"/upload")
	return fmt.Errorf("%w\n  signed envelope kept at %s\n  %s", cause, kept, upload)
}
