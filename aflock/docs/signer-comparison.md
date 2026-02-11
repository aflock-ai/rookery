# Signer Feature Comparison: Witness vs Aflock

## Architecture

| Feature | Witness | Aflock |
|---------|---------|--------|
| **Execution Model** | CLI-based, wraps commands | MCP server, persistent daemon |
| **Primary Use Case** | CI/CD pipeline attestation | AI agent tool execution attestation |
| **Plugin Architecture** | Registry-based provider pattern | Direct SPIRE integration |
| **Client Interface** | CLI commands | MCP JSON-RPC over stdio |

## Signing Mechanisms

| Feature | Witness | Aflock |
|---------|---------|--------|
| **RSA** | ✅ 2048/3072/4096 | ❌ Not implemented |
| **ECDSA** | ✅ P-256/384/521 | ✅ P-256 (via SPIRE) |
| **Ed25519** | ✅ File-based | ❌ Not implemented |
| **Hash Algorithms** | SHA224/256/384/512 | SHA256 |

## Key Management Backends

| Backend | Witness | Aflock |
|---------|---------|--------|
| **SPIFFE/SPIRE** | ✅ Workload API | ✅ Workload API |
| **AWS KMS** | ✅ ARN/Alias/KeyID | ❌ Not implemented |
| **GCP KMS** | ✅ URI format | ❌ Not implemented |
| **Azure Key Vault** | ✅ Env auth | ❌ Not implemented |
| **HashiCorp Vault** | ✅ PKI engine | ❌ Not implemented |
| **Sigstore/Fulcio** | ✅ Keyless OIDC | ❌ Not implemented |
| **File-based Keys** | ✅ PEM with passphrase | ❌ Not implemented |

## Attestation Format

| Feature | Witness | Aflock |
|---------|---------|--------|
| **Format** | in-toto + DSSE | in-toto + DSSE |
| **Statement Type** | `https://in-toto.io/Statement/v1` | `https://in-toto.io/Statement/v1` |
| **Predicate Types** | 30+ attestors | `action/v0.1` (tool calls) |
| **Multi-signature** | ✅ | ❌ Single signature |
| **Certificate Chain** | ✅ Leaf + intermediates | ✅ Via SPIRE |
| **Timestamps** | ✅ RFC3161 TSA | ❌ Not implemented |

## Identity Model

| Feature | Witness | Aflock |
|---------|---------|--------|
| **Identity Source** | SPIFFE ID from SVID | SPIFFE ID + Transitive Identity |
| **Transitive Identity** | ❌ | ✅ (model → binary → env → policy) |
| **Identity Hash** | ❌ | ✅ SHA256 of identity chain |
| **Model Constraints** | ❌ | ✅ AI model + version |
| **Policy Binding** | Via policy file | Policy digest in identity |

## Attestation Content

| Attestor Type | Witness | Aflock |
|---------------|---------|--------|
| **Command Execution** | ✅ `commandrun` | ✅ Bash tool calls |
| **File Operations** | ✅ `material`/`product` | ✅ Read/Write tracking |
| **Environment** | ✅ 30+ attestors | ✅ Environment type |
| **Git Context** | ✅ | ❌ (could be added) |
| **SBOM** | ✅ Syft integration | ❌ |
| **Docker/OCI** | ✅ | ✅ Container detection |
| **Session Metrics** | ❌ | ✅ Tokens, cost, turns |

## Policy & Verification

| Feature | Witness | Aflock |
|---------|---------|--------|
| **Policy Format** | in-toto layout | Custom JSON |
| **Policy Engine** | OPA Rego | Built-in evaluator |
| **Functionary Support** | ✅ Keys/KMS refs | ✅ SPIFFE patterns |
| **Threshold Signatures** | ✅ | ❌ |
| **Offline Verification** | ✅ | ✅ |

## Unique to Aflock

| Feature | Description |
|---------|-------------|
| **Transitive Agent Identity** | Hash of (model, binary, env, tools, policy, parent) |
| **AI Model Versioning** | Model name + version in attestations |
| **Session Metrics** | Token counts, cost tracking, turn numbers |
| **Tool Use Tracking** | Per-tool-call attestations with decision |
| **MCP Integration** | Native Model Context Protocol support |
| **Policy Enforcement** | Real-time allow/deny decisions |
| **Arbitrary Attestation** | `sign_attestation` tool for custom data |

## Unique to Witness

| Feature | Description |
|---------|-------------|
| **30+ Attestor Types** | Comprehensive SDLC coverage |
| **Multi-KMS Support** | AWS, GCP, Azure, Vault |
| **Keyless Signing** | Fulcio/Sigstore OIDC integration |
| **RFC3161 Timestamps** | Temporal proof from TSA |
| **Threshold Policies** | Multi-party signing requirements |
| **Process Tracing** | Linux ptrace for tampering detection |
| **SARIF Integration** | Security scan results |
| **SBOM Generation** | Syft-powered SBOM creation |

## Recommendations for Aflock

### High Priority
1. **Add KMS Support** - Reuse witness `signer/kms/` packages for AWS/GCP/Azure
2. **Fulcio Integration** - Enable keyless signing for CI/CD environments
3. **RFC3161 Timestamps** - Add temporal proof for audit trails

### Medium Priority
4. **Multi-signature** - Support multiple functionaries per attestation
5. **File-based Keys** - Fallback when SPIRE unavailable
6. **Git Attestor** - Capture git context for code provenance

### Low Priority
7. **Vault Integration** - Dynamic certificate generation
8. **SBOM Attestor** - Software bill of materials
9. **Threshold Policies** - Multi-party approval workflows
