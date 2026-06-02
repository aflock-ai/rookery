// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//go:build cilocktelemetrytest

package telemetry

import "os"

// This file compiles ONLY under the `cilocktelemetrytest` build tag, which the
// release pipeline never sets. It exists so the telemetry CI smoke gate can build
// a cilock binary (`go build -tags cilocktelemetrytest`) whose analytics endpoint
// is redirected to a local mock hub via CILOCK_TELEMETRY_ENDPOINT_FOR_TEST. That
// lets the gate assert exactly what the shipped binary POSTs — and that an
// opted-out run POSTs nothing — without ever contacting the production hub.
//
// SECURITY: the production binary is built WITHOUT this tag, so it never reads the
// endpoint from the environment; `endpoint` stays the hardcoded
// analytics.testifysec.com value in telemetry.go. An attacker who controls a
// victim's environment therefore cannot redirect (and capture) the victim's
// telemetry — the override simply does not exist in shipped builds.
func init() {
	if v := os.Getenv("CILOCK_TELEMETRY_ENDPOINT_FOR_TEST"); v != "" {
		endpoint = v
	}
}
