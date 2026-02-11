#!/bin/bash
# Integration test for aflock CLI
# Tests full session lifecycle: start -> tools -> end -> verify

set -e

AFLOCK_BIN="${AFLOCK_BIN:-./bin/aflock}"
TEST_PROJECT="./test-project"
SESSION_ID="integration-test-$(date +%s)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

pass_count=0
fail_count=0

pass() {
    echo -e "${GREEN}PASS${NC}: $1"
    pass_count=$((pass_count + 1))
}

fail() {
    echo -e "${RED}FAIL${NC}: $1"
    echo "  Expected: $2"
    echo "  Got: $3"
    fail_count=$((fail_count + 1))
}

skip() {
    echo -e "${YELLOW}SKIP${NC}: $1"
}

echo "=========================================="
echo "aflock Integration Test"
echo "Session: $SESSION_ID"
echo "=========================================="
echo ""

# Test 1: SessionStart
echo "--- Test 1: SessionStart ---"
session_result=$(echo "{\"session_id\":\"$SESSION_ID\",\"hook_event_name\":\"SessionStart\",\"cwd\":\"$TEST_PROJECT\",\"source\":\"startup\"}" | $AFLOCK_BIN --hook SessionStart)

if echo "$session_result" | grep -q "hookEventName.*SessionStart"; then
    pass "SessionStart returns valid response"
else
    fail "SessionStart returns valid response" "hookEventName: SessionStart" "$session_result"
fi

if echo "$session_result" | grep -q "test-policy"; then
    pass "SessionStart loads correct policy"
else
    fail "SessionStart loads correct policy" "test-policy" "$session_result"
fi

# Test 2: PreToolUse - Allow
echo ""
echo "--- Test 2: PreToolUse (Allow) ---"
allow_result=$(echo "{\"session_id\":\"$SESSION_ID\",\"hook_event_name\":\"PreToolUse\",\"cwd\":\"$TEST_PROJECT\",\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\"main.go\"}}" | $AFLOCK_BIN --hook PreToolUse)

if echo "$allow_result" | grep -q '"permissionDecision":"allow"'; then
    pass "PreToolUse allows Read tool"
else
    fail "PreToolUse allows Read tool" "permissionDecision: allow" "$allow_result"
fi

# Test 3: PreToolUse - Deny
echo ""
echo "--- Test 3: PreToolUse (Deny) ---"
deny_result=$(echo "{\"session_id\":\"$SESSION_ID\",\"hook_event_name\":\"PreToolUse\",\"cwd\":\"$TEST_PROJECT\",\"tool_name\":\"Task\",\"tool_input\":{\"prompt\":\"do something\"}}" | $AFLOCK_BIN --hook PreToolUse 2>&1) || true

if echo "$deny_result" | grep -q "BLOCKED"; then
    pass "PreToolUse blocks Task tool"
else
    fail "PreToolUse blocks Task tool" "BLOCKED message" "$deny_result"
fi

# Test 4: PreToolUse - Require Approval
echo ""
echo "--- Test 4: PreToolUse (Require Approval) ---"
approval_result=$(echo "{\"session_id\":\"$SESSION_ID\",\"hook_event_name\":\"PreToolUse\",\"cwd\":\"$TEST_PROJECT\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"rm -rf /tmp/test\"}}" | $AFLOCK_BIN --hook PreToolUse)

if echo "$approval_result" | grep -q '"permissionDecision":"ask"'; then
    pass "PreToolUse requires approval for rm command"
else
    fail "PreToolUse requires approval for rm command" "permissionDecision: ask" "$approval_result"
fi

# Test 5: PreToolUse - File access deny
echo ""
echo "--- Test 5: PreToolUse (File Deny) ---"
file_deny_result=$(echo "{\"session_id\":\"$SESSION_ID\",\"hook_event_name\":\"PreToolUse\",\"cwd\":\"$TEST_PROJECT\",\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\".env\"}}" | $AFLOCK_BIN --hook PreToolUse 2>&1) || true

if echo "$file_deny_result" | grep -q "BLOCKED"; then
    pass "PreToolUse blocks .env file access"
else
    fail "PreToolUse blocks .env file access" "BLOCKED message" "$file_deny_result"
fi

# Test 6: PostToolUse
echo ""
echo "--- Test 6: PostToolUse ---"
post_result=$(echo "{\"session_id\":\"$SESSION_ID\",\"hook_event_name\":\"PostToolUse\",\"cwd\":\"$TEST_PROJECT\",\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\"main.go\"},\"tool_result\":{\"content\":\"package main\"}}" | $AFLOCK_BIN --hook PostToolUse)

# PostToolUse returns empty {} or with hookSpecificOutput - both are valid
if echo "$post_result" | grep -qE '^\{\}$|hookSpecificOutput'; then
    pass "PostToolUse records tool execution"
else
    fail "PostToolUse records tool execution" "{} or hookSpecificOutput" "$post_result"
fi

# Test 7: SessionEnd
echo ""
echo "--- Test 7: SessionEnd ---"
end_result=$(echo "{\"session_id\":\"$SESSION_ID\",\"hook_event_name\":\"SessionEnd\",\"cwd\":\"$TEST_PROJECT\"}" | $AFLOCK_BIN --hook SessionEnd 2>&1)

# SessionEnd returns empty {} (logs to stderr) - both stdout {} and stderr metrics message are valid
if echo "$end_result" | grep -qE '^\{\}$|Session ended'; then
    pass "SessionEnd completes session"
else
    fail "SessionEnd completes session" "{} or 'Session ended'" "$end_result"
fi

# Test 8: Verify
echo ""
echo "--- Test 8: Verify Session ---"
verify_result=$($AFLOCK_BIN verify "$SESSION_ID")

# JSON output has whitespace, so check for the key-value pairs
if echo "$verify_result" | grep -q '"success": true'; then
    pass "Verify confirms session success"
else
    fail "Verify confirms session success" "success: true" "$verify_result"
fi

if echo "$verify_result" | grep -q '"policyName": "test-policy"'; then
    pass "Verify shows correct policy"
else
    fail "Verify shows correct policy" "policyName: test-policy" "$verify_result"
fi

# Test 9: Status lists session
echo ""
echo "--- Test 9: Status Lists Session ---"
status_result=$($AFLOCK_BIN status)

if echo "$status_result" | grep -q "$SESSION_ID"; then
    pass "Status lists the test session"
else
    fail "Status lists the test session" "Session ID in list" "$status_result"
fi

# Summary
echo ""
echo "=========================================="
echo "Summary"
echo "=========================================="
echo -e "${GREEN}Passed${NC}: $pass_count"
echo -e "${RED}Failed${NC}: $fail_count"
echo ""

if [ $fail_count -gt 0 ]; then
    exit 1
fi

echo "All tests passed!"
