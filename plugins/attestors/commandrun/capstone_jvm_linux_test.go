// Copyright 2026 The Rookery Contributors
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

//go:build linux

// V2 Phase 11 — Capstone B: JVM workload (Spring PetClinic).
//
// The JVM is the workload class that hung V1's single-goroutine
// dispatcher. JVM startup scans the classpath — opens tens of
// thousands of .class files from ~/.m2/repository and from the
// app's own jars, just to wire up reflection. A real Spring Boot
// build like spring-petclinic compounds this: javac compiles 50+
// .java sources, spring-boot-maven-plugin repackages into a fat
// jar, Surefire test execution forks a separate JVM. If the
// dispatcher drops events here the attestation will have holes.
//
// Source layout: the test reads CILOCK_CAPSTONE_PETCLINIC_SRC for
// the path to a cloned spring-petclinic checkout. If unset OR the
// path doesn't have a pom.xml, the test t.Skips cleanly.
//
// Run:
//   sudo -E env "PATH=$PATH CILOCK_CAPSTONE_PETCLINIC_SRC=/root/spring-petclinic" \
//     go test -tags linux -timeout 60m -run TestCapstone_JVM -v ./plugins/attestors/commandrun

package commandrun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
)

const capstonePetClinicSrcEnv = "CILOCK_CAPSTONE_PETCLINIC_SRC"

// TestCapstone_JVM_SpringPetClinic is the V2 ship-gate JVM
// capstone — the workload class that broke V1.
//
// Workload: `./mvnw clean package -DskipTests -B -q` against a
// spring-petclinic checkout. Pulls hundreds of dependencies from
// Maven Central, compiles ~50 Java sources, runs the Spring Boot
// repackager to build a fat jar.
//
// Pass criteria (same correctness invariants as the kernel
// capstone — attestation completeness is non-negotiable):
//   - The build itself succeeds (cilock didn't break Maven via
//     dispatcher backpressure or fd interference).
//   - ZERO nil-digest entries across all per-process OpenedFiles.
//     Holes here would mean an attacker could swap a classpath
//     jar and the attestation wouldn't catch it.
//   - The repackaged Spring Boot jar appears in products or
//     intermediates (Maven re-reads its own output during the
//     repackage stage).
//   - Process tree shows real depth — javac forks, surefire forks,
//     maven plugin executions fork. Below ~20 processes means
//     watched-bit propagation broke under JVM forking patterns.
func TestCapstone_JVM_SpringPetClinic(t *testing.T) {
	if testing.Short() {
		t.Skip("capstone test — skip in -short mode")
	}
	srcDir := os.Getenv(capstonePetClinicSrcEnv)
	if srcDir == "" {
		t.Skipf("set %s=<spring-petclinic path> to run the JVM capstone", capstonePetClinicSrcEnv)
	}
	if _, err := os.Stat(filepath.Join(srcDir, "pom.xml")); err != nil {
		t.Skipf("spring-petclinic pom.xml not found at %s: %v", srcDir, err)
	}
	if !diskHasGB(t, srcDir, 3) {
		t.Skipf("need ≥3 GB free at %s for Maven build + local repo", srcDir)
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	// Wipe any prior build output (without nuking the local Maven
	// repo — re-downloading every dep on each run is gratuitous).
	mustRun(t, srcDir, "rm", "-rf", "target")

	t.Logf("starting Spring PetClinic Maven build under cilock eBPF trace…")
	start := time.Now()

	// -DskipTests: tests are great but Spring Boot's test slice
	//   pulls another ~200 jars (mockito, byte-buddy, junit-jupiter,
	//   spring-test, h2). Skipping them keeps the workload focused
	//   on the JVM/compile/repackage path. The classpath scan
	//   ON THE COMPILE side is the killer for V1's dispatcher,
	//   so this is already the right test.
	// -B: batch mode (no interactive progress bars in logs).
	// -q: quiet (just warnings + errors).
	cap := runCrossLang(t, srcDir,
		[]string{"./mvnw", "clean", "package", "-DskipTests", "-B", "-q"},
		nil,
	)
	dur := time.Since(start)

	if cap.rc.ExitCode != 0 {
		t.Fatalf("Maven build FAILED (exit=%d) after %s — cilock broke the build", cap.rc.ExitCode, dur)
	}
	t.Logf("Maven build succeeded in %s under cilock trace", dur)

	// (1) The Spring Boot jar must land in products or intermediates.
	// Spring Boot repackages: javac → target/classes/, then spring-
	// boot-maven-plugin re-reads target/<name>-SNAPSHOT.jar and
	// repackages it. That re-read flips classification to
	// intermediate, which is correct.
	//
	// The basename includes a version: spring-petclinic-4.0.0-SNAPSHOT.jar
	// (and a .original sibling left behind by the repackage plugin —
	// either of those satisfies the capstone). Match by substring +
	// .jar suffix, not exact basename.
	jarPath := findJarMatching(cap, "spring-petclinic")
	if jarPath == "" {
		t.Fatalf("spring-petclinic jar NOT in products or intermediates — capstone FAILED.\n%s", cap.summarize())
	}
	t.Logf("spring-petclinic jar captured at: %s", jarPath)

	// (2) At least one .class file in intermediates — javac output.
	// Spring's PetClinicApplication is the canonical entrypoint
	// class in this app.
	if cap.requireIntermediate("PetClinicApplication.class") == "" {
		t.Errorf("PetClinicApplication.class NOT in intermediates — javac output capture broke under JVM workload")
	}

	// (3) THE attestation correctness invariant — zero nil digests.
	// JVM workloads are the highest-risk case for holes: thousands
	// of classpath opens, fast-exit forked workers. Every entry in
	// OpenedFiles must have a non-nil digest. UnhashedOpens with a
	// reason is the right place for any gap; nil-digest OpenedFiles
	// entries are holes an attacker could exploit.
	var nilDigests uint64
	var nilSamples []string
	for _, p := range cap.rc.Processes {
		for path, ds := range p.OpenedFiles {
			if ds == nil {
				nilDigests++
				if len(nilSamples) < 10 {
					nilSamples = append(nilSamples, path)
				}
			}
		}
	}
	if nilDigests > 0 {
		t.Errorf("attestation incomplete: %d per-process OpenedFiles entries have nil digests. "+
			"NONE are acceptable — every one is a hole an attacker could exploit.\nSamples: %v",
			nilDigests, nilSamples)
	}

	if cap.rc.Summary != nil {
		d := cap.rc.Summary.Diagnostics
		totalFiles := uint64(len(cap.Materials) + len(cap.Intermediates) + len(cap.Products) + len(cap.CacheArtifacts))
		t.Logf("coverage: %d files captured, %d nil-digest entries, %d transient hash failures; "+
			"event drops openat=%d readTap=%d",
			totalFiles, nilDigests, d.FallbackHashFailures,
			d.RingbufOpenatDrops, d.RingbufReadTapDrops)
	}

	// (4) Process tree depth — Maven forks compiler workers and
	// plugin executions; we should see real depth.
	if len(cap.rc.Processes) < 10 {
		t.Errorf("only %d processes captured for a Maven build — process-tree propagation broke under JVM forking",
			len(cap.rc.Processes))
	}

	t.Logf("CAPSTONE PASSED: materials=%d intermediates=%d products=%d cache=%d procs=%d in %s",
		len(cap.Materials), len(cap.Intermediates), len(cap.Products), len(cap.CacheArtifacts),
		len(cap.rc.Processes), dur)
}

// findJarMatching returns the first product- or intermediate-path
// whose basename contains substr AND ends in .jar. Spring Boot's
// repackaged artifact is named like `<artifact>-<version>.jar`, so
// requireWritten's exact-basename match misses it.
func findJarMatching(cap *xlangCapture, substr string) string {
	hit := func(set map[string]attestation.CaptureEntry) string {
		for path := range set {
			base := filepath.Base(path)
			if strings.Contains(base, substr) && strings.HasSuffix(base, ".jar") {
				return path
			}
		}
		return ""
	}
	if h := hit(cap.Products); h != "" {
		return h
	}
	return hit(cap.Intermediates)
}
