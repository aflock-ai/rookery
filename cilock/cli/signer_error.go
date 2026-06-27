// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import "errors"

func onlyOneSignerError() error {
	return errors.New("only one signer is supported; choose one --signer-* source. " +
		"If this happened after `cilock login` while using a local key, pass --platform-url \"\" " +
		"for a fully offline command or run `cilock logout` before retrying")
}
