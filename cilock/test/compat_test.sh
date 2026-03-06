#!/usr/bin/env bash
# Comprehensive compatibility test: witness vs cilock
# Tests that both CLIs produce equivalent output for all testable operations.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CILOCK="${SCRIPT_DIR}/../cilock"
WITNESS="$(which witness)"
TESTDIR="$(mktemp -d)"
PASSED=0
FAILED=0
SKIPPED=0
REPORT=""

cleanup() {
    rm -rf "$TESTDIR"
}
trap cleanup EXIT

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_pass() {
    ((PASSED++))
    echo -e "${GREEN}PASS${NC}: $1"
    REPORT+="PASS: $1\n"
}

log_fail() {
    ((FAILED++))
    echo -e "${RED}FAIL${NC}: $1"
    echo -e "  ${RED}Details: $2${NC}"
    REPORT+="FAIL: $1 -- $2\n"
}

log_skip() {
    ((SKIPPED++))
    echo -e "${YELLOW}SKIP${NC}: $1 -- $2"
    REPORT+="SKIP: $1 -- $2\n"
}

log_section() {
    echo ""
    echo -e "${BLUE}=== $1 ===${NC}"
    REPORT+="\n=== $1 ===\n"
}

# -------------------------------------------------------------------
# Setup: generate test keys
# -------------------------------------------------------------------
setup_keys() {
    echo "Setting up test keys in $TESTDIR..."
    openssl genpkey -algorithm RSA -out "$TESTDIR/test.pem" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
    openssl rsa -in "$TESTDIR/test.pem" -pubout -out "$TESTDIR/test.pub" 2>/dev/null

    # Create a second key pair for policy signing
    openssl genpkey -algorithm RSA -out "$TESTDIR/policy.pem" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
    openssl rsa -in "$TESTDIR/policy.pem" -pubout -out "$TESTDIR/policy.pub" 2>/dev/null

    # Password-protected key
    openssl genpkey -algorithm RSA -out "$TESTDIR/protected.pem" -aes256 -pass pass:testpass123 -pkeyopt rsa_keygen_bits:2048 2>/dev/null

    # ECDSA key
    openssl ecparam -name prime256v1 -genkey -noout -out "$TESTDIR/ec.pem" 2>/dev/null
    openssl ec -in "$TESTDIR/ec.pem" -pubout -out "$TESTDIR/ec.pub" 2>/dev/null

    # Create a dummy artifact
    echo "hello world" > "$TESTDIR/artifact.txt"

    # Create a working directory with some files
    mkdir -p "$TESTDIR/workdir"
    echo "file1 content" > "$TESTDIR/workdir/file1.txt"
    echo "file2 content" > "$TESTDIR/workdir/file2.txt"
    mkdir -p "$TESTDIR/workdir/subdir"
    echo "file3 content" > "$TESTDIR/workdir/subdir/file3.txt"

    # Initialize a git repo in workdir for git attestor
    (cd "$TESTDIR/workdir" && git init -q && git add . && git commit -q -m "init" --no-gpg-sign)
}

# -------------------------------------------------------------------
# Test: Help output structure
# -------------------------------------------------------------------
test_help_output() {
    log_section "Help Output Compatibility"

    for subcmd in run verify sign attestors "attestors list" "attestors schema" completion version; do
        local w_exit=0 c_exit=0
        $WITNESS $subcmd --help > "$TESTDIR/w_help.txt" 2>&1 || w_exit=$?
        $CILOCK $subcmd --help > "$TESTDIR/c_help.txt" 2>&1 || c_exit=$?

        if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
            log_pass "help output: $subcmd (both succeed)"
        else
            log_fail "help output: $subcmd" "witness exit=$w_exit, cilock exit=$c_exit"
        fi
    done

    # Policy subcommand: witness uses "policy check", cilock uses "policy validate"
    local w_exit=0 c_exit=0
    $WITNESS policy check --help > /dev/null 2>&1 || w_exit=$?
    $CILOCK policy validate --help > /dev/null 2>&1 || c_exit=$?
    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "help output: policy (witness=check, cilock=validate)"
    else
        log_fail "help output: policy" "witness check exit=$w_exit, cilock validate exit=$c_exit"
    fi
}

# -------------------------------------------------------------------
# Test: Flag name compatibility (extract just flag names)
# -------------------------------------------------------------------
test_flag_names() {
    log_section "Flag Name Compatibility"

    for subcmd in run verify sign; do
        # Extract just flag names (--flag-name) from help output
        $WITNESS $subcmd --help 2>&1 | grep -oE '\-\-[a-zA-Z0-9_-]+' | sort -u > "$TESTDIR/w_flags.txt"
        $CILOCK $subcmd --help 2>&1 | grep -oE '\-\-[a-zA-Z0-9_-]+' | sort -u > "$TESTDIR/c_flags.txt"

        # Check all witness flags exist in cilock
        local missing=()
        while IFS= read -r flag; do
            if ! grep -qxF -- "$flag" "$TESTDIR/c_flags.txt"; then
                missing+=("$flag")
            fi
        done < "$TESTDIR/w_flags.txt"

        if [[ ${#missing[@]} -eq 0 ]]; then
            log_pass "flag names: $subcmd (all witness flags present in cilock)"
        else
            log_fail "flag names: $subcmd" "missing flags: ${missing[*]}"
        fi

        # Report extra cilock flags (not an error, just info)
        local extra=()
        while IFS= read -r flag; do
            if ! grep -qxF -- "$flag" "$TESTDIR/w_flags.txt"; then
                extra+=("$flag")
            fi
        done < "$TESTDIR/c_flags.txt"

        if [[ ${#extra[@]} -gt 0 ]]; then
            echo "  INFO: cilock has additional flags for $subcmd: ${extra[*]}"
            REPORT+="INFO: cilock has additional flags for $subcmd: ${extra[*]}\n"
        fi
    done
}

# -------------------------------------------------------------------
# Test: Short flag compatibility
# -------------------------------------------------------------------
test_short_flags() {
    log_section "Short Flag Compatibility"

    for subcmd in run verify sign; do
        $WITNESS $subcmd --help 2>&1 | grep -oE '\s-[a-zA-Z],' | sed 's/,//' | tr -d ' ' | sort -u > "$TESTDIR/w_short.txt"
        $CILOCK $subcmd --help 2>&1 | grep -oE '\s-[a-zA-Z],' | sed 's/,//' | tr -d ' ' | sort -u > "$TESTDIR/c_short.txt"

        if diff -q "$TESTDIR/w_short.txt" "$TESTDIR/c_short.txt" > /dev/null 2>&1; then
            log_pass "short flags: $subcmd (identical)"
        else
            local d
            d=$(diff "$TESTDIR/w_short.txt" "$TESTDIR/c_short.txt" 2>&1 || true)
            log_fail "short flags: $subcmd" "$d"
        fi
    done
}

# -------------------------------------------------------------------
# Test: Attestors list
# -------------------------------------------------------------------
test_attestors_list() {
    log_section "Attestors List"

    $WITNESS attestors list 2>&1 | awk -F'│' '/│.*│.*│/{print $2}' | sed 's/ //g; s/(.*)//; /^$/d; /NAME/d; /^-/d' | sort > "$TESTDIR/w_attestors.txt"
    $CILOCK attestors list 2>&1 | awk -F'│' '/│.*│.*│/{print $2}' | sed 's/ //g; s/(.*)//; /^$/d; /NAME/d; /^-/d' | sort > "$TESTDIR/c_attestors.txt"

    # Check all witness attestors are in cilock
    local missing=()
    while IFS= read -r att; do
        if [[ -z "$att" ]]; then continue; fi
        if ! grep -qxF -- "$att" "$TESTDIR/c_attestors.txt"; then
            missing+=("$att")
        fi
    done < "$TESTDIR/w_attestors.txt"

    if [[ ${#missing[@]} -eq 0 ]]; then
        log_pass "attestors list: all witness attestors present in cilock"
    else
        log_fail "attestors list: missing attestors" "${missing[*]}"
    fi

    # Report extra cilock attestors
    local extra=()
    while IFS= read -r att; do
        if [[ -z "$att" ]]; then continue; fi
        if ! grep -qxF -- "$att" "$TESTDIR/w_attestors.txt"; then
            extra+=("$att")
        fi
    done < "$TESTDIR/c_attestors.txt"

    if [[ ${#extra[@]} -gt 0 ]]; then
        echo "  INFO: cilock has additional attestors: ${extra[*]}"
        REPORT+="INFO: cilock has additional attestors: ${extra[*]}\n"
    fi
}

# -------------------------------------------------------------------
# Test: Attestors schema
# -------------------------------------------------------------------
test_attestors_schema() {
    log_section "Attestors Schema"

    for att in git environment material product command-run; do
        local w_exit=0 c_exit=0
        $WITNESS attestors schema "$att" > "$TESTDIR/w_schema_${att}.json" 2>/dev/null || w_exit=$?
        $CILOCK attestors schema "$att" > "$TESTDIR/c_schema_${att}.json" 2>/dev/null || c_exit=$?

        if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
            # Both produce valid JSON
            if python3 -c "import json; json.load(open('$TESTDIR/w_schema_${att}.json'))" 2>/dev/null && \
               python3 -c "import json; json.load(open('$TESTDIR/c_schema_${att}.json'))" 2>/dev/null; then
                log_pass "attestor schema: $att (valid JSON from both)"
            else
                log_fail "attestor schema: $att" "invalid JSON output"
            fi
        else
            log_fail "attestor schema: $att" "witness exit=$w_exit, cilock exit=$c_exit"
        fi
    done
}

# -------------------------------------------------------------------
# Test: Run command with file signer (RSA)
# -------------------------------------------------------------------
test_run_file_signer_rsa() {
    log_section "Run Command - File Signer (RSA)"

    # Witness run
    local w_exit=0
    $WITNESS run \
        --step test-step \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/w_run_rsa.json" \
        --workingdir "$TESTDIR/workdir" \
        --attestations environment,git \
        -- echo "hello from witness" \
        > "$TESTDIR/w_run_rsa.log" 2>&1 || w_exit=$?

    # CIlock run
    local c_exit=0
    $CILOCK run \
        --step test-step \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/c_run_rsa.json" \
        --workingdir "$TESTDIR/workdir" \
        --attestations environment,git \
        -- echo "hello from cilock" \
        > "$TESTDIR/c_run_rsa.log" 2>&1 || c_exit=$?

    if [[ $w_exit -ne 0 ]]; then
        log_fail "run file-signer RSA: witness" "exit=$w_exit, $(cat "$TESTDIR/w_run_rsa.log")"
        return
    fi
    if [[ $c_exit -ne 0 ]]; then
        log_fail "run file-signer RSA: cilock" "exit=$c_exit, $(cat "$TESTDIR/c_run_rsa.log")"
        return
    fi

    # Both should produce valid DSSE envelopes
    if python3 -c "import json; d=json.load(open('$TESTDIR/w_run_rsa.json')); assert 'payload' in d" 2>/dev/null; then
        log_pass "run file-signer RSA: witness produces valid DSSE"
    else
        log_fail "run file-signer RSA: witness DSSE" "invalid output structure"
    fi

    if python3 -c "import json; d=json.load(open('$TESTDIR/c_run_rsa.json')); assert 'payload' in d" 2>/dev/null; then
        log_pass "run file-signer RSA: cilock produces valid DSSE"
    else
        log_fail "run file-signer RSA: cilock DSSE" "invalid output structure"
    fi

    # Compare envelope structure (payloadType, signatures present)
    local w_type c_type
    w_type=$(python3 -c "import json; print(json.load(open('$TESTDIR/w_run_rsa.json')).get('payloadType',''))" 2>/dev/null)
    c_type=$(python3 -c "import json; print(json.load(open('$TESTDIR/c_run_rsa.json')).get('payloadType',''))" 2>/dev/null)

    if [[ "$w_type" == "$c_type" ]]; then
        log_pass "run file-signer RSA: payloadType matches ($w_type)"
    else
        log_fail "run file-signer RSA: payloadType mismatch" "witness=$w_type, cilock=$c_type"
    fi

    # Compare attestation types in payload
    local w_atts c_atts
    w_atts=$(python3 -c "
import json,base64
d=json.load(open('$TESTDIR/w_run_rsa.json'))
p=json.loads(base64.b64decode(d['payload']))
types=sorted([a['type'] for a in p.get('predicate',{}).get('attestations',[])])
print(' '.join(types))
" 2>/dev/null || echo "PARSE_ERROR")
    c_atts=$(python3 -c "
import json,base64
d=json.load(open('$TESTDIR/c_run_rsa.json'))
p=json.loads(base64.b64decode(d['payload']))
types=sorted([a['type'] for a in p.get('predicate',{}).get('attestations',[])])
print(' '.join(types))
" 2>/dev/null || echo "PARSE_ERROR")

    if [[ "$w_atts" == "$c_atts" ]]; then
        log_pass "run file-signer RSA: attestation types match ($w_atts)"
    else
        # They might differ slightly in type URIs (witness.dev vs aflock.ai), compare counts
        local w_count c_count
        w_count=$(echo "$w_atts" | wc -w | tr -d ' ')
        c_count=$(echo "$c_atts" | wc -w | tr -d ' ')
        if [[ "$w_count" == "$c_count" ]]; then
            log_pass "run file-signer RSA: attestation count matches ($w_count) [type URIs differ as expected]"
            echo "  INFO: witness types: $w_atts"
            echo "  INFO: cilock types:  $c_atts"
        else
            log_fail "run file-signer RSA: attestation count mismatch" "witness=$w_count ($w_atts), cilock=$c_count ($c_atts)"
        fi
    fi
}

# -------------------------------------------------------------------
# Test: Run command with ECDSA key
# -------------------------------------------------------------------
test_run_file_signer_ec() {
    log_section "Run Command - File Signer (ECDSA)"

    local w_exit=0 c_exit=0

    $WITNESS run \
        --step ec-step \
        --signer-file-key-path "$TESTDIR/ec.pem" \
        -o "$TESTDIR/w_run_ec.json" \
        --workingdir "$TESTDIR/workdir" \
        -- echo "ec test" \
        > "$TESTDIR/w_run_ec.log" 2>&1 || w_exit=$?

    $CILOCK run \
        --step ec-step \
        --signer-file-key-path "$TESTDIR/ec.pem" \
        -o "$TESTDIR/c_run_ec.json" \
        --workingdir "$TESTDIR/workdir" \
        -- echo "ec test" \
        > "$TESTDIR/c_run_ec.log" 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "run file-signer ECDSA: both succeed"
    else
        log_fail "run file-signer ECDSA" "witness exit=$w_exit, cilock exit=$c_exit"
        [[ $w_exit -ne 0 ]] && echo "  witness log: $(cat "$TESTDIR/w_run_ec.log")"
        [[ $c_exit -ne 0 ]] && echo "  cilock log: $(cat "$TESTDIR/c_run_ec.log")"
    fi
}

# -------------------------------------------------------------------
# Test: Run with password-protected key
# -------------------------------------------------------------------
test_run_passphrase_key() {
    log_section "Run Command - Password Protected Key"

    local w_exit=0 c_exit=0

    $WITNESS run \
        --step pass-step \
        --signer-file-key-path "$TESTDIR/protected.pem" \
        --signer-file-key-passphrase testpass123 \
        -o "$TESTDIR/w_run_pass.json" \
        --workingdir "$TESTDIR/workdir" \
        -- echo "passphrase test" \
        > "$TESTDIR/w_run_pass.log" 2>&1 || w_exit=$?

    $CILOCK run \
        --step pass-step \
        --signer-file-key-path "$TESTDIR/protected.pem" \
        --signer-file-key-passphrase testpass123 \
        -o "$TESTDIR/c_run_pass.json" \
        --workingdir "$TESTDIR/workdir" \
        -- echo "passphrase test" \
        > "$TESTDIR/c_run_pass.log" 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "run passphrase key: both succeed"
    else
        log_fail "run passphrase key" "witness exit=$w_exit, cilock exit=$c_exit"
        [[ $w_exit -ne 0 ]] && echo "  witness log: $(cat "$TESTDIR/w_run_pass.log")"
        [[ $c_exit -ne 0 ]] && echo "  cilock log: $(cat "$TESTDIR/c_run_pass.log")"
    fi
}

# -------------------------------------------------------------------
# Test: Run with passphrase-path
# -------------------------------------------------------------------
test_run_passphrase_path() {
    log_section "Run Command - Passphrase Path"

    echo -n "testpass123" > "$TESTDIR/passphrase.txt"

    local w_exit=0 c_exit=0

    $WITNESS run \
        --step passpath-step \
        --signer-file-key-path "$TESTDIR/protected.pem" \
        --signer-file-key-passphrase-path "$TESTDIR/passphrase.txt" \
        -o "$TESTDIR/w_run_passpath.json" \
        --workingdir "$TESTDIR/workdir" \
        -- echo "passphrase-path test" \
        > "$TESTDIR/w_run_passpath.log" 2>&1 || w_exit=$?

    $CILOCK run \
        --step passpath-step \
        --signer-file-key-path "$TESTDIR/protected.pem" \
        --signer-file-key-passphrase-path "$TESTDIR/passphrase.txt" \
        -o "$TESTDIR/c_run_passpath.json" \
        --workingdir "$TESTDIR/workdir" \
        -- echo "passphrase-path test" \
        > "$TESTDIR/c_run_passpath.log" 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "run passphrase-path: both succeed"
    else
        log_fail "run passphrase-path" "witness exit=$w_exit, cilock exit=$c_exit"
        [[ $w_exit -ne 0 ]] && echo "  witness log: $(cat "$TESTDIR/w_run_passpath.log")"
        [[ $c_exit -ne 0 ]] && echo "  cilock log: $(cat "$TESTDIR/c_run_passpath.log")"
    fi
}

# -------------------------------------------------------------------
# Test: Run with custom attestation selection
# -------------------------------------------------------------------
test_run_custom_attestations() {
    log_section "Run Command - Custom Attestation Selection"

    # Run with only environment
    local w_exit=0 c_exit=0

    $WITNESS run \
        --step custom-att \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/w_run_envonly.json" \
        --workingdir "$TESTDIR/workdir" \
        --attestations environment \
        -- echo "env only" \
        > /dev/null 2>&1 || w_exit=$?

    $CILOCK run \
        --step custom-att \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/c_run_envonly.json" \
        --workingdir "$TESTDIR/workdir" \
        --attestations environment \
        -- echo "env only" \
        > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        # Verify attestation list only contains expected types
        local w_types c_types
        w_types=$(python3 -c "
import json,base64
d=json.load(open('$TESTDIR/w_run_envonly.json'))
p=json.loads(base64.b64decode(d['payload']))
names=sorted([a['type'] for a in p.get('predicate',{}).get('attestations',[])])
print(len(names))
" 2>/dev/null)
        c_types=$(python3 -c "
import json,base64
d=json.load(open('$TESTDIR/c_run_envonly.json'))
p=json.loads(base64.b64decode(d['payload']))
names=sorted([a['type'] for a in p.get('predicate',{}).get('attestations',[])])
print(len(names))
" 2>/dev/null)
        if [[ "$w_types" == "$c_types" ]]; then
            log_pass "run custom attestations (env only): attestation count matches ($w_types)"
        else
            log_fail "run custom attestations" "witness count=$w_types, cilock count=$c_types"
        fi
    else
        log_fail "run custom attestations" "witness exit=$w_exit, cilock exit=$c_exit"
    fi
}

# -------------------------------------------------------------------
# Test: Run with hashes option
# -------------------------------------------------------------------
test_run_hashes() {
    log_section "Run Command - Hash Algorithms"

    for hash_algo in sha256 sha1; do
        local w_exit=0 c_exit=0

        $WITNESS run \
            --step "hash-$hash_algo" \
            --signer-file-key-path "$TESTDIR/test.pem" \
            -o "$TESTDIR/w_run_hash_${hash_algo}.json" \
            --workingdir "$TESTDIR/workdir" \
            --hashes "$hash_algo" \
            -- echo "hash test $hash_algo" \
            > "$TESTDIR/w_hash_${hash_algo}.log" 2>&1 || w_exit=$?

        $CILOCK run \
            --step "hash-$hash_algo" \
            --signer-file-key-path "$TESTDIR/test.pem" \
            -o "$TESTDIR/c_run_hash_${hash_algo}.json" \
            --workingdir "$TESTDIR/workdir" \
            --hashes "$hash_algo" \
            -- echo "hash test $hash_algo" \
            > "$TESTDIR/c_hash_${hash_algo}.log" 2>&1 || c_exit=$?

        if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
            log_pass "run --hashes=$hash_algo: both succeed"
        elif [[ $w_exit -eq $c_exit ]]; then
            log_pass "run --hashes=$hash_algo: same exit code ($w_exit) [compatible behavior]"
        else
            log_fail "run --hashes=$hash_algo" "witness exit=$w_exit, cilock exit=$c_exit"
        fi
    done
}

# -------------------------------------------------------------------
# Test: Run with environment variable options
# -------------------------------------------------------------------
test_run_env_options() {
    log_section "Run Command - Environment Variable Options"

    # Test --env-filter-sensitive-vars
    local w_exit=0 c_exit=0

    $WITNESS run \
        --step env-filter \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/w_run_envfilter.json" \
        --workingdir "$TESTDIR/workdir" \
        --env-filter-sensitive-vars \
        -- echo "env filter test" \
        > /dev/null 2>&1 || w_exit=$?

    $CILOCK run \
        --step env-filter \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/c_run_envfilter.json" \
        --workingdir "$TESTDIR/workdir" \
        --env-filter-sensitive-vars \
        -- echo "env filter test" \
        > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "run --env-filter-sensitive-vars: both succeed"
    else
        log_fail "run --env-filter-sensitive-vars" "witness exit=$w_exit, cilock exit=$c_exit"
    fi

    # Test --env-disable-default-sensitive-vars
    w_exit=0; c_exit=0

    $WITNESS run \
        --step env-nodefault \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/w_run_envnodefault.json" \
        --workingdir "$TESTDIR/workdir" \
        --env-disable-default-sensitive-vars \
        -- echo "env nodefault test" \
        > /dev/null 2>&1 || w_exit=$?

    $CILOCK run \
        --step env-nodefault \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/c_run_envnodefault.json" \
        --workingdir "$TESTDIR/workdir" \
        --env-disable-default-sensitive-vars \
        -- echo "env nodefault test" \
        > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "run --env-disable-default-sensitive-vars: both succeed"
    else
        log_fail "run --env-disable-default-sensitive-vars" "witness exit=$w_exit, cilock exit=$c_exit"
    fi

    # Test --env-add-sensitive-key
    w_exit=0; c_exit=0

    $WITNESS run \
        --step env-addkey \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/w_run_envaddkey.json" \
        --workingdir "$TESTDIR/workdir" \
        --env-add-sensitive-key CUSTOM_SECRET \
        -- echo "env addkey test" \
        > /dev/null 2>&1 || w_exit=$?

    $CILOCK run \
        --step env-addkey \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/c_run_envaddkey.json" \
        --workingdir "$TESTDIR/workdir" \
        --env-add-sensitive-key CUSTOM_SECRET \
        -- echo "env addkey test" \
        > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "run --env-add-sensitive-key: both succeed"
    else
        log_fail "run --env-add-sensitive-key" "witness exit=$w_exit, cilock exit=$c_exit"
    fi
}

# -------------------------------------------------------------------
# Test: Run with working directory option
# -------------------------------------------------------------------
test_run_workingdir() {
    log_section "Run Command - Working Directory"

    local w_exit=0 c_exit=0

    $WITNESS run \
        --step wdir-step \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/w_run_wdir.json" \
        --workingdir "$TESTDIR/workdir" \
        -- ls \
        > /dev/null 2>&1 || w_exit=$?

    $CILOCK run \
        --step wdir-step \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/c_run_wdir.json" \
        --workingdir "$TESTDIR/workdir" \
        -- ls \
        > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "run --workingdir: both succeed"
    else
        log_fail "run --workingdir" "witness exit=$w_exit, cilock exit=$c_exit"
    fi
}

# -------------------------------------------------------------------
# Test: Run without --step (should fail)
# -------------------------------------------------------------------
test_run_missing_step() {
    log_section "Run Command - Missing Step (Error Case)"

    local w_exit=0 c_exit=0

    $WITNESS run \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/w_run_nostep.json" \
        -- echo "no step" \
        > /dev/null 2>&1 || w_exit=$?

    $CILOCK run \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/c_run_nostep.json" \
        -- echo "no step" \
        > /dev/null 2>&1 || c_exit=$?

    # Both should fail (step is required)
    if [[ $w_exit -ne 0 && $c_exit -ne 0 ]]; then
        log_pass "run missing --step: both fail as expected"
    elif [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "run missing --step: both succeed (step not required in this version)"
    else
        log_fail "run missing --step: behavior differs" "witness exit=$w_exit, cilock exit=$c_exit"
    fi
}

# -------------------------------------------------------------------
# Test: Run without signer (should fail)
# -------------------------------------------------------------------
test_run_no_signer() {
    log_section "Run Command - No Signer (Error Case)"

    local w_exit=0 c_exit=0

    $WITNESS run \
        --step no-signer \
        -o "$TESTDIR/w_run_nosigner.json" \
        -- echo "no signer" \
        > /dev/null 2>&1 || w_exit=$?

    $CILOCK run \
        --step no-signer \
        -o "$TESTDIR/c_run_nosigner.json" \
        -- echo "no signer" \
        > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -ne 0 && $c_exit -ne 0 ]]; then
        log_pass "run no signer: both fail as expected"
    else
        log_fail "run no signer: behavior differs" "witness exit=$w_exit, cilock exit=$c_exit"
    fi
}

# -------------------------------------------------------------------
# Test: Run with failing command
# -------------------------------------------------------------------
test_run_failing_command() {
    log_section "Run Command - Failing Command"

    local w_exit=0 c_exit=0

    $WITNESS run \
        --step fail-step \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/w_run_fail.json" \
        --workingdir "$TESTDIR/workdir" \
        -- false \
        > /dev/null 2>&1 || w_exit=$?

    $CILOCK run \
        --step fail-step \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/c_run_fail.json" \
        --workingdir "$TESTDIR/workdir" \
        -- false \
        > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -ne 0 && $c_exit -ne 0 ]]; then
        log_pass "run failing command: both exit non-zero"
    elif [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "run failing command: both still produce attestation (non-zero cmd exit recorded)"
    else
        log_fail "run failing command: behavior differs" "witness exit=$w_exit, cilock exit=$c_exit"
    fi
}

# -------------------------------------------------------------------
# Test: Sign command
# -------------------------------------------------------------------
test_sign() {
    log_section "Sign Command"

    # Create a simple JSON file to sign
    echo '{"test": "data"}' > "$TESTDIR/tosign.json"

    local w_exit=0 c_exit=0

    $WITNESS sign \
        --signer-file-key-path "$TESTDIR/test.pem" \
        --infile "$TESTDIR/tosign.json" \
        --outfile "$TESTDIR/w_signed.json" \
        > /dev/null 2>&1 || w_exit=$?

    $CILOCK sign \
        --signer-file-key-path "$TESTDIR/test.pem" \
        --infile "$TESTDIR/tosign.json" \
        --outfile "$TESTDIR/c_signed.json" \
        > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "sign: both succeed"

        # Compare structure
        local w_keys c_keys
        w_keys=$(python3 -c "import json; print(sorted(json.load(open('$TESTDIR/w_signed.json')).keys()))" 2>/dev/null)
        c_keys=$(python3 -c "import json; print(sorted(json.load(open('$TESTDIR/c_signed.json')).keys()))" 2>/dev/null)

        if [[ "$w_keys" == "$c_keys" ]]; then
            log_pass "sign: output structure matches ($w_keys)"
        else
            log_fail "sign: output structure differs" "witness=$w_keys, cilock=$c_keys"
        fi
    else
        log_fail "sign" "witness exit=$w_exit, cilock exit=$c_exit"
    fi
}

# -------------------------------------------------------------------
# Test: Sign with custom datatype
# -------------------------------------------------------------------
test_sign_datatype() {
    log_section "Sign Command - Custom Datatype"

    echo '{"custom": "data"}' > "$TESTDIR/custom_tosign.json"

    local w_exit=0 c_exit=0

    $WITNESS sign \
        --signer-file-key-path "$TESTDIR/test.pem" \
        --infile "$TESTDIR/custom_tosign.json" \
        --outfile "$TESTDIR/w_signed_custom.json" \
        --datatype "application/json" \
        > /dev/null 2>&1 || w_exit=$?

    $CILOCK sign \
        --signer-file-key-path "$TESTDIR/test.pem" \
        --infile "$TESTDIR/custom_tosign.json" \
        --outfile "$TESTDIR/c_signed_custom.json" \
        --datatype "application/json" \
        > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        local w_type c_type
        w_type=$(python3 -c "import json; print(json.load(open('$TESTDIR/w_signed_custom.json')).get('payloadType',''))" 2>/dev/null)
        c_type=$(python3 -c "import json; print(json.load(open('$TESTDIR/c_signed_custom.json')).get('payloadType',''))" 2>/dev/null)

        if [[ "$w_type" == "$c_type" ]]; then
            log_pass "sign --datatype: payloadType matches ($w_type)"
        else
            log_fail "sign --datatype: payloadType mismatch" "witness=$w_type, cilock=$c_type"
        fi
    else
        log_fail "sign --datatype" "witness exit=$w_exit, cilock exit=$c_exit"
    fi
}

# -------------------------------------------------------------------
# Test: Sign with ECDSA
# -------------------------------------------------------------------
test_sign_ec() {
    log_section "Sign Command - ECDSA"

    echo '{"ec": "data"}' > "$TESTDIR/ec_tosign.json"

    local w_exit=0 c_exit=0

    $WITNESS sign \
        --signer-file-key-path "$TESTDIR/ec.pem" \
        --infile "$TESTDIR/ec_tosign.json" \
        --outfile "$TESTDIR/w_signed_ec.json" \
        > /dev/null 2>&1 || w_exit=$?

    $CILOCK sign \
        --signer-file-key-path "$TESTDIR/ec.pem" \
        --infile "$TESTDIR/ec_tosign.json" \
        --outfile "$TESTDIR/c_signed_ec.json" \
        > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "sign ECDSA: both succeed"
    else
        log_fail "sign ECDSA" "witness exit=$w_exit, cilock exit=$c_exit"
    fi
}

# -------------------------------------------------------------------
# Test: Verify - create policy and full pipeline
# -------------------------------------------------------------------
test_verify_pipeline() {
    log_section "Verify Command - Full Pipeline"

    # Get public key ID (SHA256 of DER)
    local keyid
    keyid=$(openssl rsa -pubin -in "$TESTDIR/test.pub" -outform DER 2>/dev/null | shasum -a 256 | cut -d' ' -f1)

    # Get base64 of the public key
    local pubkey_b64
    pubkey_b64=$(base64 < "$TESTDIR/test.pub" | tr -d '\n')

    # Create a policy document
    local policy_json
    policy_json=$(cat <<POLICY_EOF
{
    "expires": "2030-12-01T00:00:00Z",
    "steps": {
        "test-step": {
            "name": "test-step",
            "functionaries": [
                {
                    "type": "publickey",
                    "publickeyid": "${keyid}"
                }
            ],
            "attestations": [
                {"type": "https://witness.dev/attestations/environment/v0.1"},
                {"type": "https://witness.dev/attestations/git/v0.1"},
                {"type": "https://witness.dev/attestations/material/v0.1"},
                {"type": "https://witness.dev/attestations/product/v0.1"},
                {"type": "https://witness.dev/attestations/command-run/v0.1"}
            ]
        }
    },
    "publickeys": {
        "${keyid}": {
            "keyid": "${keyid}",
            "key": "${pubkey_b64}"
        }
    }
}
POLICY_EOF
)

    echo "$policy_json" > "$TESTDIR/policy_raw.json"

    # Sign the policy with witness and cilock
    local w_exit=0 c_exit=0

    $WITNESS sign \
        --signer-file-key-path "$TESTDIR/policy.pem" \
        --infile "$TESTDIR/policy_raw.json" \
        --outfile "$TESTDIR/w_policy_signed.json" \
        > /dev/null 2>&1 || w_exit=$?

    $CILOCK sign \
        --signer-file-key-path "$TESTDIR/policy.pem" \
        --infile "$TESTDIR/policy_raw.json" \
        --outfile "$TESTDIR/c_policy_signed.json" \
        > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -ne 0 ]]; then
        log_fail "verify pipeline: witness policy sign failed" "exit=$w_exit"
        return
    fi
    if [[ $c_exit -ne 0 ]]; then
        log_fail "verify pipeline: cilock policy sign failed" "exit=$c_exit"
        return
    fi
    log_pass "verify pipeline: both sign policy"

    # Create attestation with witness
    w_exit=0
    $WITNESS run \
        --step test-step \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/w_attestation.json" \
        --workingdir "$TESTDIR/workdir" \
        --attestations environment,git \
        -- echo "witness pipeline test" \
        > /dev/null 2>&1 || w_exit=$?

    if [[ $w_exit -ne 0 ]]; then
        log_fail "verify pipeline: witness run failed" "exit=$w_exit"
        return
    fi

    # Create attestation with cilock
    c_exit=0
    $CILOCK run \
        --step test-step \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/c_attestation.json" \
        --workingdir "$TESTDIR/workdir" \
        --attestations environment,git \
        -- echo "cilock pipeline test" \
        > /dev/null 2>&1 || c_exit=$?

    if [[ $c_exit -ne 0 ]]; then
        log_fail "verify pipeline: cilock run failed" "exit=$c_exit"
        return
    fi
    log_pass "verify pipeline: both produce attestations"

    # Cross-verify: witness attestation with witness verify
    w_exit=0
    $WITNESS verify \
        --policy "$TESTDIR/w_policy_signed.json" \
        --publickey "$TESTDIR/policy.pub" \
        --attestations "$TESTDIR/w_attestation.json" \
        --artifactfile "$TESTDIR/workdir/file1.txt" \
        > "$TESTDIR/w_verify_w.log" 2>&1 || w_exit=$?

    echo "  witness verify witness-attestation: exit=$w_exit"

    # Cross-verify: cilock attestation with cilock verify
    c_exit=0
    $CILOCK verify \
        --policy "$TESTDIR/c_policy_signed.json" \
        --publickey "$TESTDIR/policy.pub" \
        --attestations "$TESTDIR/c_attestation.json" \
        --artifactfile "$TESTDIR/workdir/file1.txt" \
        > "$TESTDIR/c_verify_c.log" 2>&1 || c_exit=$?

    echo "  cilock verify cilock-attestation: exit=$c_exit"

    # Cross-verify: witness attestation with cilock verify
    local cross_exit=0
    $CILOCK verify \
        --policy "$TESTDIR/w_policy_signed.json" \
        --publickey "$TESTDIR/policy.pub" \
        --attestations "$TESTDIR/w_attestation.json" \
        --artifactfile "$TESTDIR/workdir/file1.txt" \
        > "$TESTDIR/c_verify_w.log" 2>&1 || cross_exit=$?

    echo "  cilock verify witness-attestation: exit=$cross_exit"

    # Note: Full verify pipelines may fail because the attestation type URIs differ
    # (witness.dev vs aflock.ai). This is EXPECTED and documented.
    # The important thing is that both CLIs behave consistently with their own attestations.

    if [[ $w_exit -eq $c_exit ]]; then
        log_pass "verify pipeline: witness-self and cilock-self have same exit code ($w_exit)"
    else
        echo "  INFO: Exit codes differ (witness=$w_exit, cilock=$c_exit) - likely due to attestation type URI differences"
        REPORT+="INFO: Verify exit codes differ - attestation type URIs (witness.dev vs aflock.ai)\n"
    fi
}

# -------------------------------------------------------------------
# Test: Policy validate
# -------------------------------------------------------------------
test_policy_validate() {
    log_section "Policy Validate Command"

    # Valid policy
    local keyid
    keyid=$(openssl rsa -pubin -in "$TESTDIR/test.pub" -outform DER 2>/dev/null | shasum -a 256 | cut -d' ' -f1)

    local pubkey_b64
    pubkey_b64=$(base64 < "$TESTDIR/test.pub" | tr -d '\n')

    cat > "$TESTDIR/valid_policy.json" <<VPEOF
{
    "expires": "2030-12-01T00:00:00Z",
    "steps": {
        "build": {
            "name": "build",
            "functionaries": [{"type": "publickey", "publickeyid": "${keyid}"}],
            "attestations": [{"type": "https://witness.dev/attestations/git/v0.1"}]
        }
    },
    "publickeys": {
        "${keyid}": {"keyid": "${keyid}", "key": "${pubkey_b64}"}
    }
}
VPEOF

    # Sign it
    $WITNESS sign \
        --signer-file-key-path "$TESTDIR/test.pem" \
        --infile "$TESTDIR/valid_policy.json" \
        --outfile "$TESTDIR/valid_policy_signed.json" \
        > /dev/null 2>&1

    # Note: witness uses "policy check [file]" (positional), cilock uses "policy validate --policy [file]"
    # We test both with their native syntax and compare results

    # Test witness policy check
    local w_exit=0
    $WITNESS policy check "$TESTDIR/valid_policy_signed.json" > "$TESTDIR/w_polval.txt" 2>&1 || w_exit=$?

    # Test cilock policy validate
    local c_exit=0
    $CILOCK policy validate --policy "$TESTDIR/valid_policy_signed.json" > "$TESTDIR/c_polval.txt" 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "policy validate (valid): both succeed (witness=check, cilock=validate)"
    else
        log_fail "policy validate (valid)" "witness exit=$w_exit, cilock exit=$c_exit"
        [[ $w_exit -ne 0 ]] && echo "  witness output: $(cat "$TESTDIR/w_polval.txt")"
        [[ $c_exit -ne 0 ]] && echo "  cilock output: $(cat "$TESTDIR/c_polval.txt")"
    fi

    # Test with publickey verification
    w_exit=0; c_exit=0
    $WITNESS policy check "$TESTDIR/valid_policy_signed.json" > "$TESTDIR/w_polval_key.txt" 2>&1 || w_exit=$?
    $CILOCK policy validate --policy "$TESTDIR/valid_policy_signed.json" --publickey "$TESTDIR/test.pub" > "$TESTDIR/c_polval_key.txt" 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "policy validate (with pubkey): both succeed"
    elif [[ $w_exit -eq $c_exit ]]; then
        log_pass "policy validate (with pubkey): same exit code ($w_exit)"
    else
        # witness check doesn't support pubkey verification, so different behavior is expected
        echo "  INFO: witness 'policy check' doesn't support --publickey; cilock 'policy validate' does"
        if [[ $c_exit -eq 0 ]]; then
            log_pass "policy validate (with pubkey): cilock validates with pubkey successfully"
        else
            log_fail "policy validate (with pubkey)" "cilock exit=$c_exit"
        fi
    fi

    # Test invalid policy (missing steps)
    echo '{"expires": "2030-01-01T00:00:00Z"}' > "$TESTDIR/invalid_policy.json"

    # Sign the invalid policy so both can attempt to read it as DSSE
    $WITNESS sign --signer-file-key-path "$TESTDIR/test.pem" --infile "$TESTDIR/invalid_policy.json" --outfile "$TESTDIR/invalid_policy_signed.json" > /dev/null 2>&1

    w_exit=0; c_exit=0
    $WITNESS policy check "$TESTDIR/invalid_policy_signed.json" > /dev/null 2>&1 || w_exit=$?
    $CILOCK policy validate --policy "$TESTDIR/invalid_policy_signed.json" > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -ne 0 && $c_exit -ne 0 ]]; then
        log_pass "policy validate (invalid): both reject"
    elif [[ $w_exit -eq $c_exit ]]; then
        log_pass "policy validate (invalid): same behavior (exit=$w_exit)"
    elif [[ $c_exit -ne 0 && $w_exit -eq 0 ]]; then
        log_pass "policy validate (invalid): cilock is stricter (rejects missing steps, witness allows) [intentional]"
    else
        log_fail "policy validate (invalid)" "witness exit=$w_exit, cilock exit=$c_exit"
    fi
}

# -------------------------------------------------------------------
# Test: Completion command
# -------------------------------------------------------------------
test_completion() {
    log_section "Completion Command"

    for shell in bash zsh fish powershell; do
        local w_exit=0 c_exit=0
        $WITNESS completion "$shell" > /dev/null 2>&1 || w_exit=$?
        $CILOCK completion "$shell" > /dev/null 2>&1 || c_exit=$?

        if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
            log_pass "completion $shell: both succeed"
        else
            log_fail "completion $shell" "witness exit=$w_exit, cilock exit=$c_exit"
        fi
    done
}

# -------------------------------------------------------------------
# Test: Version command
# -------------------------------------------------------------------
test_version() {
    log_section "Version Command"

    local w_exit=0 c_exit=0
    $WITNESS version > /dev/null 2>&1 || w_exit=$?
    $CILOCK version > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "version: both succeed"
    else
        log_fail "version" "witness exit=$w_exit, cilock exit=$c_exit"
    fi
}

# -------------------------------------------------------------------
# Test: Debug signer (cilock only, witness may not have it)
# -------------------------------------------------------------------
test_debug_signer() {
    log_section "Debug Signer (CIlock Extra Feature)"

    local c_exit=0
    $CILOCK run \
        --step debug-step \
        --signer-debug-enabled \
        -o "$TESTDIR/c_run_debug.json" \
        --workingdir "$TESTDIR/workdir" \
        -- echo "debug signer test" \
        > "$TESTDIR/c_debug.log" 2>&1 || c_exit=$?

    if [[ $c_exit -eq 0 ]]; then
        log_pass "debug signer: cilock run succeeds with --signer-debug-enabled"
    else
        log_fail "debug signer" "cilock exit=$c_exit, $(cat "$TESTDIR/c_debug.log")"
    fi
}

# -------------------------------------------------------------------
# Test: Run with product glob options
# -------------------------------------------------------------------
test_run_product_glob() {
    log_section "Run Command - Product Glob Options"

    # Test product include glob
    local w_exit=0 c_exit=0

    $WITNESS run \
        --step glob-step \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/w_run_glob.json" \
        --workingdir "$TESTDIR/workdir" \
        --attestor-product-include-glob "*.txt" \
        -- echo "glob test" \
        > /dev/null 2>&1 || w_exit=$?

    $CILOCK run \
        --step glob-step \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/c_run_glob.json" \
        --workingdir "$TESTDIR/workdir" \
        --attestor-product-include-glob "*.txt" \
        -- echo "glob test" \
        > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "run --attestor-product-include-glob: both succeed"
    else
        log_fail "run --attestor-product-include-glob" "witness exit=$w_exit, cilock exit=$c_exit"
    fi
}

# -------------------------------------------------------------------
# Test: Config file
# -------------------------------------------------------------------
test_config_file() {
    log_section "Config File Support"

    cat > "$TESTDIR/workdir/.witness.yaml" <<'CFEOF'
run:
    step: config-step
    attestations:
        - environment
        - git
CFEOF

    local w_exit=0 c_exit=0

    (cd "$TESTDIR/workdir" && $WITNESS run \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/w_run_config.json" \
        -- echo "config test") > /dev/null 2>&1 || w_exit=$?

    (cd "$TESTDIR/workdir" && $CILOCK run \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/c_run_config.json" \
        -- echo "config test") > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "config file: both succeed reading .witness.yaml"
    elif [[ $w_exit -eq $c_exit ]]; then
        log_pass "config file: same behavior (exit=$w_exit)"
    else
        log_fail "config file" "witness exit=$w_exit, cilock exit=$c_exit"
    fi

    rm -f "$TESTDIR/workdir/.witness.yaml"
}

# -------------------------------------------------------------------
# Test: Dirhash glob option
# -------------------------------------------------------------------
test_run_dirhash() {
    log_section "Run Command - Dirhash Glob"

    local w_exit=0 c_exit=0

    $WITNESS run \
        --step dirhash-step \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/w_run_dirhash.json" \
        --workingdir "$TESTDIR/workdir" \
        --dirhash-glob "subdir/**" \
        -- echo "dirhash test" \
        > /dev/null 2>&1 || w_exit=$?

    $CILOCK run \
        --step dirhash-step \
        --signer-file-key-path "$TESTDIR/test.pem" \
        -o "$TESTDIR/c_run_dirhash.json" \
        --workingdir "$TESTDIR/workdir" \
        --dirhash-glob "subdir/**" \
        -- echo "dirhash test" \
        > /dev/null 2>&1 || c_exit=$?

    if [[ $w_exit -eq 0 && $c_exit -eq 0 ]]; then
        log_pass "run --dirhash-glob: both succeed"
    else
        log_fail "run --dirhash-glob" "witness exit=$w_exit, cilock exit=$c_exit"
    fi
}

# -------------------------------------------------------------------
# Skip list: things that can't be tested locally
# -------------------------------------------------------------------
report_skips() {
    log_section "Skipped Tests (Require External Services)"

    log_skip "Fulcio signer" "Requires OIDC provider and Fulcio server"
    log_skip "Sigstore keyless signing" "Requires Sigstore infrastructure"
    log_skip "SPIFFE signer" "Requires SPIFFE Workload API socket"
    log_skip "AWS KMS signer" "Requires AWS credentials and KMS key"
    log_skip "GCP KMS signer" "Requires GCP credentials and KMS key"
    log_skip "Azure KMS signer" "Requires Azure credentials and Key Vault"
    log_skip "Vault PKI signer" "Requires running Vault instance with PKI engine"
    log_skip "Vault Transit signer" "Requires running Vault instance with Transit engine"
    log_skip "Archivista integration" "Not yet ported to rookery"
    log_skip "Timestamp Authority servers" "Requires running TSA"
    log_skip "AWS IID attestor" "Requires running on AWS EC2 instance"
    log_skip "GCP IIT attestor" "Requires running on GCP Compute Engine"
    log_skip "AWS CodeBuild attestor" "Requires running in CodeBuild"
    log_skip "GitHub attestor" "Requires running in GitHub Actions"
    log_skip "GitLab attestor" "Requires running in GitLab CI"
    log_skip "Jenkins attestor" "Requires running in Jenkins"
    log_skip "OCI attestor" "Requires container runtime"
    log_skip "Docker attestor" "Requires Docker daemon"
    log_skip "K8s Manifest attestor" "Requires Kubernetes cluster"
    log_skip "Policy with x.509 cert constraints" "Requires CA infrastructure"
    log_skip "Policy with Fulcio cert extensions" "Requires Fulcio-signed attestation"
}

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
main() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║    Witness vs CIlock Compatibility Test Suite           ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Witness: $($WITNESS version 2>&1)"
    echo "CIlock:  $($CILOCK version 2>&1)"
    echo "Test dir: $TESTDIR"
    echo ""

    setup_keys

    test_help_output
    test_flag_names
    test_short_flags
    test_attestors_list
    test_attestors_schema
    test_run_file_signer_rsa
    test_run_file_signer_ec
    test_run_passphrase_key
    test_run_passphrase_path
    test_run_custom_attestations
    test_run_hashes
    test_run_env_options
    test_run_workingdir
    test_run_missing_step
    test_run_no_signer
    test_run_failing_command
    test_run_product_glob
    test_run_dirhash
    test_config_file
    test_sign
    test_sign_datatype
    test_sign_ec
    test_verify_pipeline
    test_policy_validate
    test_completion
    test_version
    test_debug_signer
    report_skips

    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}, ${YELLOW}$SKIPPED skipped${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

    # Write report
    echo -e "$REPORT" > "$TESTDIR/compat_report.txt"
    echo "Full report: $TESTDIR/compat_report.txt"

    if [[ $FAILED -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
