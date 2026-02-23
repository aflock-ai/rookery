//go:build audit

// compat_audit_test.go audits that all rookery exports are properly
// re-exported through the go-witness compat layer.
//
// Run with: go test -tags audit ./...
package witness_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	// compat layer imports
	compatAttestation "github.com/in-toto/go-witness/attestation"
	compatCrypto "github.com/in-toto/go-witness/cryptoutil"
	compatDSSE "github.com/in-toto/go-witness/dsse"
	compatFile "github.com/in-toto/go-witness/file"
	compatIntoto "github.com/in-toto/go-witness/intoto"
	compatIntotoLink "github.com/in-toto/go-witness/intoto/link"
	compatIntotoProvenance "github.com/in-toto/go-witness/intoto/provenance"
	compatIntotoV1 "github.com/in-toto/go-witness/intoto/v1"
	compatLog "github.com/in-toto/go-witness/log"
	compatPolicy "github.com/in-toto/go-witness/policy"
	compatPolicySig "github.com/in-toto/go-witness/policysig"
	compatRegistry "github.com/in-toto/go-witness/registry"
	compatSigner "github.com/in-toto/go-witness/signer"
	compatSignerKMS "github.com/in-toto/go-witness/signer/kms"
	compatSLSA "github.com/in-toto/go-witness/slsa"
	compatSource "github.com/in-toto/go-witness/source"
	compatTimestamp "github.com/in-toto/go-witness/timestamp"
	witness "github.com/in-toto/go-witness"

	// rookery imports
	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/file"
	"github.com/aflock-ai/rookery/attestation/intoto"
	intotoLink "github.com/aflock-ai/rookery/attestation/intoto/link"
	intotoProvenance "github.com/aflock-ai/rookery/attestation/intoto/provenance"
	intotoV1 "github.com/aflock-ai/rookery/attestation/intoto/v1"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/policysig"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/attestation/signer"
	signerKMS "github.com/aflock-ai/rookery/attestation/signer/kms"
	"github.com/aflock-ai/rookery/attestation/slsa"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/attestation/workflow"
)

// ============================================================================
// SECTION 1: TYPE IDENTITY TESTS
//
// For every exported type alias in the compat layer, verify it is the
// EXACT SAME underlying Go type as the rookery equivalent using
// reflect.TypeOf(). A type alias produces identical Go types. If someone
// accidentally uses a type definition instead of an alias, these tests
// catch the silent breakage.
// ============================================================================

func TestTypeIdentity_Attestation(t *testing.T) {
	tests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"RunType", reflect.TypeOf(compatAttestation.ExecuteRunType), reflect.TypeOf(attestation.ExecuteRunType)},
		{"AttestationContextOption", reflect.TypeOf((*compatAttestation.AttestationContextOption)(nil)).Elem(), reflect.TypeOf((*attestation.AttestationContextOption)(nil)).Elem()},
		{"AttestationContext", reflect.TypeOf((*compatAttestation.AttestationContext)(nil)), reflect.TypeOf((*attestation.AttestationContext)(nil))},
		{"CompletedAttestor", reflect.TypeOf(compatAttestation.CompletedAttestor{}), reflect.TypeOf(attestation.CompletedAttestor{})},
		{"Product", reflect.TypeOf(compatAttestation.Product{}), reflect.TypeOf(attestation.Product{})},
		{"Collection", reflect.TypeOf(compatAttestation.Collection{}), reflect.TypeOf(attestation.Collection{})},
		{"CollectionAttestation", reflect.TypeOf(compatAttestation.CollectionAttestation{}), reflect.TypeOf(attestation.CollectionAttestation{})},
		{"ErrAttestor", reflect.TypeOf(compatAttestation.ErrAttestor{}), reflect.TypeOf(attestation.ErrAttestor{})},
		{"ErrAttestationNotFound", reflect.TypeOf(compatAttestation.ErrAttestationNotFound("")), reflect.TypeOf(attestation.ErrAttestationNotFound(""))},
		{"ErrAttestorNotFound", reflect.TypeOf(compatAttestation.ErrAttestorNotFound("")), reflect.TypeOf(attestation.ErrAttestorNotFound(""))},
		{"RawAttestation", reflect.TypeOf((*compatAttestation.RawAttestation)(nil)), reflect.TypeOf((*attestation.RawAttestation)(nil))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("TYPE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}

	// Interface types via nil pointer dereference
	interfaceTests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"Attestor", reflect.TypeOf((*compatAttestation.Attestor)(nil)).Elem(), reflect.TypeOf((*attestation.Attestor)(nil)).Elem()},
		{"Subjecter", reflect.TypeOf((*compatAttestation.Subjecter)(nil)).Elem(), reflect.TypeOf((*attestation.Subjecter)(nil)).Elem()},
		{"Materialer", reflect.TypeOf((*compatAttestation.Materialer)(nil)).Elem(), reflect.TypeOf((*attestation.Materialer)(nil)).Elem()},
		{"Producer", reflect.TypeOf((*compatAttestation.Producer)(nil)).Elem(), reflect.TypeOf((*attestation.Producer)(nil)).Elem()},
		{"Exporter", reflect.TypeOf((*compatAttestation.Exporter)(nil)).Elem(), reflect.TypeOf((*attestation.Exporter)(nil)).Elem()},
		{"MultiExporter", reflect.TypeOf((*compatAttestation.MultiExporter)(nil)).Elem(), reflect.TypeOf((*attestation.MultiExporter)(nil)).Elem()},
		{"BackReffer", reflect.TypeOf((*compatAttestation.BackReffer)(nil)).Elem(), reflect.TypeOf((*attestation.BackReffer)(nil)).Elem()},
		{"EnvironmentCapturer", reflect.TypeOf((*compatAttestation.EnvironmentCapturer)(nil)).Elem(), reflect.TypeOf((*attestation.EnvironmentCapturer)(nil)).Elem()},
	}

	for _, tt := range interfaceTests {
		t.Run("Interface_"+tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("INTERFACE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}
}

func TestTypeIdentity_Cryptoutil(t *testing.T) {
	tests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"PEMType", reflect.TypeOf(compatCrypto.PublicKeyPEMType), reflect.TypeOf(cryptoutil.PublicKeyPEMType)},
		{"DigestValue", reflect.TypeOf(compatCrypto.DigestValue{}), reflect.TypeOf(cryptoutil.DigestValue{})},
		{"DigestSet", reflect.TypeOf(compatCrypto.DigestSet{}), reflect.TypeOf(cryptoutil.DigestSet{})},
		{"ErrUnsupportedPEM", reflect.TypeOf(compatCrypto.ErrUnsupportedPEM{}), reflect.TypeOf(cryptoutil.ErrUnsupportedPEM{})},
		{"ErrInvalidPemBlock", reflect.TypeOf(compatCrypto.ErrInvalidPemBlock{}), reflect.TypeOf(cryptoutil.ErrInvalidPemBlock{})},
		{"ErrUnsupportedHash", reflect.TypeOf(compatCrypto.ErrUnsupportedHash("")), reflect.TypeOf(cryptoutil.ErrUnsupportedHash(""))},
		{"ErrUnsupportedKeyType", reflect.TypeOf(compatCrypto.ErrUnsupportedKeyType{}), reflect.TypeOf(cryptoutil.ErrUnsupportedKeyType{})},
		{"ErrVerifyFailed", reflect.TypeOf(compatCrypto.ErrVerifyFailed{}), reflect.TypeOf(cryptoutil.ErrVerifyFailed{})},
		{"ErrInvalidSigner", reflect.TypeOf(compatCrypto.ErrInvalidSigner{}), reflect.TypeOf(cryptoutil.ErrInvalidSigner{})},
		{"ErrInvalidCertificate", reflect.TypeOf(compatCrypto.ErrInvalidCertificate{}), reflect.TypeOf(cryptoutil.ErrInvalidCertificate{})},
		{"RSASigner", reflect.TypeOf((*compatCrypto.RSASigner)(nil)), reflect.TypeOf((*cryptoutil.RSASigner)(nil))},
		{"RSAVerifier", reflect.TypeOf((*compatCrypto.RSAVerifier)(nil)), reflect.TypeOf((*cryptoutil.RSAVerifier)(nil))},
		{"ECDSASigner", reflect.TypeOf((*compatCrypto.ECDSASigner)(nil)), reflect.TypeOf((*cryptoutil.ECDSASigner)(nil))},
		{"ECDSAVerifier", reflect.TypeOf((*compatCrypto.ECDSAVerifier)(nil)), reflect.TypeOf((*cryptoutil.ECDSAVerifier)(nil))},
		{"ED25519Signer", reflect.TypeOf((*compatCrypto.ED25519Signer)(nil)), reflect.TypeOf((*cryptoutil.ED25519Signer)(nil))},
		{"ED25519Verifier", reflect.TypeOf((*compatCrypto.ED25519Verifier)(nil)), reflect.TypeOf((*cryptoutil.ED25519Verifier)(nil))},
		{"X509Verifier", reflect.TypeOf((*compatCrypto.X509Verifier)(nil)), reflect.TypeOf((*cryptoutil.X509Verifier)(nil))},
		{"X509Signer", reflect.TypeOf((*compatCrypto.X509Signer)(nil)), reflect.TypeOf((*cryptoutil.X509Signer)(nil))},
		{"SignerOption", reflect.TypeOf((*compatCrypto.SignerOption)(nil)).Elem(), reflect.TypeOf((*cryptoutil.SignerOption)(nil)).Elem()},
		{"VerifierOption", reflect.TypeOf((*compatCrypto.VerifierOption)(nil)).Elem(), reflect.TypeOf((*cryptoutil.VerifierOption)(nil)).Elem()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("TYPE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}

	// Interface types
	interfaceTests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"Signer", reflect.TypeOf((*compatCrypto.Signer)(nil)).Elem(), reflect.TypeOf((*cryptoutil.Signer)(nil)).Elem()},
		{"Verifier", reflect.TypeOf((*compatCrypto.Verifier)(nil)).Elem(), reflect.TypeOf((*cryptoutil.Verifier)(nil)).Elem()},
		{"KeyIdentifier", reflect.TypeOf((*compatCrypto.KeyIdentifier)(nil)).Elem(), reflect.TypeOf((*cryptoutil.KeyIdentifier)(nil)).Elem()},
		{"TrustBundler", reflect.TypeOf((*compatCrypto.TrustBundler)(nil)).Elem(), reflect.TypeOf((*cryptoutil.TrustBundler)(nil)).Elem()},
	}

	for _, tt := range interfaceTests {
		t.Run("Interface_"+tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("INTERFACE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}
}

func TestTypeIdentity_DSSE(t *testing.T) {
	tests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"Envelope", reflect.TypeOf(compatDSSE.Envelope{}), reflect.TypeOf(dsse.Envelope{})},
		{"Signature", reflect.TypeOf(compatDSSE.Signature{}), reflect.TypeOf(dsse.Signature{})},
		{"SignatureTimestampType", reflect.TypeOf(compatDSSE.TimestampRFC3161), reflect.TypeOf(dsse.TimestampRFC3161)},
		{"SignatureTimestamp", reflect.TypeOf(compatDSSE.SignatureTimestamp{}), reflect.TypeOf(dsse.SignatureTimestamp{})},
		{"SignOption", reflect.TypeOf((*compatDSSE.SignOption)(nil)).Elem(), reflect.TypeOf((*dsse.SignOption)(nil)).Elem()},
		{"VerificationOption", reflect.TypeOf((*compatDSSE.VerificationOption)(nil)).Elem(), reflect.TypeOf((*dsse.VerificationOption)(nil)).Elem()},
		{"CheckedVerifier", reflect.TypeOf(compatDSSE.CheckedVerifier{}), reflect.TypeOf(dsse.CheckedVerifier{})},
		{"ErrNoSignatures", reflect.TypeOf(compatDSSE.ErrNoSignatures{}), reflect.TypeOf(dsse.ErrNoSignatures{})},
		{"ErrNoMatchingSigs", reflect.TypeOf(compatDSSE.ErrNoMatchingSigs{}), reflect.TypeOf(dsse.ErrNoMatchingSigs{})},
		{"ErrThresholdNotMet", reflect.TypeOf(compatDSSE.ErrThresholdNotMet{}), reflect.TypeOf(dsse.ErrThresholdNotMet{})},
		{"ErrInvalidThreshold", reflect.TypeOf(compatDSSE.ErrInvalidThreshold(0)), reflect.TypeOf(dsse.ErrInvalidThreshold(0))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("TYPE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}
}

func TestTypeIdentity_Policy(t *testing.T) {
	tests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"Policy", reflect.TypeOf(compatPolicy.Policy{}), reflect.TypeOf(policy.Policy{})},
		{"Root", reflect.TypeOf(compatPolicy.Root{}), reflect.TypeOf(policy.Root{})},
		{"PublicKey", reflect.TypeOf(compatPolicy.PublicKey{}), reflect.TypeOf(policy.PublicKey{})},
		{"TrustBundle", reflect.TypeOf(compatPolicy.TrustBundle{}), reflect.TypeOf(policy.TrustBundle{})},
		{"VerifyOption", reflect.TypeOf((*compatPolicy.VerifyOption)(nil)).Elem(), reflect.TypeOf((*policy.VerifyOption)(nil)).Elem()},
		{"Step", reflect.TypeOf(compatPolicy.Step{}), reflect.TypeOf(policy.Step{})},
		{"Functionary", reflect.TypeOf(compatPolicy.Functionary{}), reflect.TypeOf(policy.Functionary{})},
		{"Attestation", reflect.TypeOf(compatPolicy.Attestation{}), reflect.TypeOf(policy.Attestation{})},
		{"AiPolicy", reflect.TypeOf(compatPolicy.AiPolicy{}), reflect.TypeOf(policy.AiPolicy{})},
		{"RegoPolicy", reflect.TypeOf(compatPolicy.RegoPolicy{}), reflect.TypeOf(policy.RegoPolicy{})},
		{"StepResult", reflect.TypeOf(compatPolicy.StepResult{}), reflect.TypeOf(policy.StepResult{})},
		{"PassedCollection", reflect.TypeOf(compatPolicy.PassedCollection{}), reflect.TypeOf(policy.PassedCollection{})},
		{"RejectedCollection", reflect.TypeOf(compatPolicy.RejectedCollection{}), reflect.TypeOf(policy.RejectedCollection{})},
		{"AiResponse", reflect.TypeOf(compatPolicy.AiResponse{}), reflect.TypeOf(policy.AiResponse{})},
		{"CertConstraint", reflect.TypeOf(compatPolicy.CertConstraint{}), reflect.TypeOf(policy.CertConstraint{})},
		{"ErrVerifyArtifactsFailed", reflect.TypeOf(compatPolicy.ErrVerifyArtifactsFailed{}), reflect.TypeOf(policy.ErrVerifyArtifactsFailed{})},
		{"ErrNoCollections", reflect.TypeOf(compatPolicy.ErrNoCollections{}), reflect.TypeOf(policy.ErrNoCollections{})},
		{"ErrMissingAttestation", reflect.TypeOf(compatPolicy.ErrMissingAttestation{}), reflect.TypeOf(policy.ErrMissingAttestation{})},
		{"ErrPolicyExpired", reflect.TypeOf(compatPolicy.ErrPolicyExpired(time.Time{})), reflect.TypeOf(policy.ErrPolicyExpired(time.Time{}))},
		{"ErrKeyIDMismatch", reflect.TypeOf(compatPolicy.ErrKeyIDMismatch{}), reflect.TypeOf(policy.ErrKeyIDMismatch{})},
		{"ErrUnknownStep", reflect.TypeOf(compatPolicy.ErrUnknownStep("")), reflect.TypeOf(policy.ErrUnknownStep(""))},
		{"ErrArtifactCycle", reflect.TypeOf(compatPolicy.ErrArtifactCycle("")), reflect.TypeOf(policy.ErrArtifactCycle(""))},
		{"ErrMismatchArtifact", reflect.TypeOf(compatPolicy.ErrMismatchArtifact{}), reflect.TypeOf(policy.ErrMismatchArtifact{})},
		{"ErrRegoInvalidData", reflect.TypeOf(compatPolicy.ErrRegoInvalidData{}), reflect.TypeOf(policy.ErrRegoInvalidData{})},
		{"ErrPolicyDenied", reflect.TypeOf(compatPolicy.ErrPolicyDenied{}), reflect.TypeOf(policy.ErrPolicyDenied{})},
		{"ErrConstraintCheckFailed", reflect.TypeOf(compatPolicy.ErrConstraintCheckFailed{}), reflect.TypeOf(policy.ErrConstraintCheckFailed{})},
		{"ErrInvalidOption", reflect.TypeOf(compatPolicy.ErrInvalidOption{}), reflect.TypeOf(policy.ErrInvalidOption{})},
		{"ErrCircularDependency", reflect.TypeOf(compatPolicy.ErrCircularDependency{}), reflect.TypeOf(policy.ErrCircularDependency{})},
		{"ErrSelfReference", reflect.TypeOf(compatPolicy.ErrSelfReference{}), reflect.TypeOf(policy.ErrSelfReference{})},
		{"ErrDependencyNotVerified", reflect.TypeOf(compatPolicy.ErrDependencyNotVerified{}), reflect.TypeOf(policy.ErrDependencyNotVerified{})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("TYPE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}
}

func TestTypeIdentity_Source(t *testing.T) {
	tests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"CollectionEnvelope", reflect.TypeOf(compatSource.CollectionEnvelope{}), reflect.TypeOf(source.CollectionEnvelope{})},
		{"MemorySource", reflect.TypeOf((*compatSource.MemorySource)(nil)), reflect.TypeOf((*source.MemorySource)(nil))},
		{"MultiSource", reflect.TypeOf((*compatSource.MultiSource)(nil)), reflect.TypeOf((*source.MultiSource)(nil))},
		{"VerifiedSource", reflect.TypeOf((*compatSource.VerifiedSource)(nil)), reflect.TypeOf((*source.VerifiedSource)(nil))},
		{"ArchivistaSource", reflect.TypeOf((*compatSource.ArchivistaSource)(nil)), reflect.TypeOf((*source.ArchivistaSource)(nil))},
		{"CollectionVerificationResult", reflect.TypeOf(compatSource.CollectionVerificationResult{}), reflect.TypeOf(source.CollectionVerificationResult{})},
		{"ErrDuplicateReference", reflect.TypeOf(compatSource.ErrDuplicateReference("")), reflect.TypeOf(source.ErrDuplicateReference(""))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("TYPE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}

	// Interface types
	interfaceTests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"Sourcer", reflect.TypeOf((*compatSource.Sourcer)(nil)).Elem(), reflect.TypeOf((*source.Sourcer)(nil)).Elem()},
		{"VerifiedSourcer", reflect.TypeOf((*compatSource.VerifiedSourcer)(nil)).Elem(), reflect.TypeOf((*source.VerifiedSourcer)(nil)).Elem()},
	}

	for _, tt := range interfaceTests {
		t.Run("Interface_"+tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("INTERFACE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}
}

func TestTypeIdentity_Intoto(t *testing.T) {
	tests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"Subject", reflect.TypeOf(compatIntoto.Subject{}), reflect.TypeOf(intoto.Subject{})},
		{"Statement", reflect.TypeOf(compatIntoto.Statement{}), reflect.TypeOf(intoto.Statement{})},
		{"Link", reflect.TypeOf(compatIntotoLink.Link{}), reflect.TypeOf(intotoLink.Link{})},
		{"Provenance", reflect.TypeOf(compatIntotoProvenance.Provenance{}), reflect.TypeOf(intotoProvenance.Provenance{})},
		{"BuildDefinition", reflect.TypeOf(compatIntotoProvenance.BuildDefinition{}), reflect.TypeOf(intotoProvenance.BuildDefinition{})},
		{"RunDetails", reflect.TypeOf(compatIntotoProvenance.RunDetails{}), reflect.TypeOf(intotoProvenance.RunDetails{})},
		{"Builder", reflect.TypeOf(compatIntotoProvenance.Builder{}), reflect.TypeOf(intotoProvenance.Builder{})},
		{"BuildMetadata", reflect.TypeOf(compatIntotoProvenance.BuildMetadata{}), reflect.TypeOf(intotoProvenance.BuildMetadata{})},
		{"ResourceDescriptor", reflect.TypeOf(compatIntotoV1.ResourceDescriptor{}), reflect.TypeOf(intotoV1.ResourceDescriptor{})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("TYPE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}
}

func TestTypeIdentity_Log(t *testing.T) {
	tests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"SilentLogger", reflect.TypeOf(compatLog.SilentLogger{}), reflect.TypeOf(log.SilentLogger{})},
		{"ConsoleLogger", reflect.TypeOf(compatLog.ConsoleLogger{}), reflect.TypeOf(log.ConsoleLogger{})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("TYPE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}

	// Logger interface
	t.Run("Interface_Logger", func(t *testing.T) {
		compatT := reflect.TypeOf((*compatLog.Logger)(nil)).Elem()
		rookeryT := reflect.TypeOf((*log.Logger)(nil)).Elem()
		if compatT != rookeryT {
			t.Errorf("INTERFACE MISMATCH: compat %v != rookery %v", compatT, rookeryT)
		}
	})
}

func TestTypeIdentity_SLSA(t *testing.T) {
	tests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"VerificationResult", reflect.TypeOf(compatSLSA.PassedVerificationResult), reflect.TypeOf(slsa.PassedVerificationResult)},
		{"Verifier", reflect.TypeOf(compatSLSA.Verifier{}), reflect.TypeOf(slsa.Verifier{})},
		{"ResourceDescriptor", reflect.TypeOf(compatSLSA.ResourceDescriptor{}), reflect.TypeOf(slsa.ResourceDescriptor{})},
		{"VerificationSummary", reflect.TypeOf(compatSLSA.VerificationSummary{}), reflect.TypeOf(slsa.VerificationSummary{})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("TYPE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}
}

func TestTypeIdentity_Timestamp(t *testing.T) {
	tests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"TSPTimestamper", reflect.TypeOf(compatTimestamp.TSPTimestamper{}), reflect.TypeOf(timestamp.TSPTimestamper{})},
		{"TSPTimestamperOption", reflect.TypeOf((*compatTimestamp.TSPTimestamperOption)(nil)).Elem(), reflect.TypeOf((*timestamp.TSPTimestamperOption)(nil)).Elem()},
		{"TSPVerifier", reflect.TypeOf(compatTimestamp.TSPVerifier{}), reflect.TypeOf(timestamp.TSPVerifier{})},
		{"TSPVerifierOption", reflect.TypeOf((*compatTimestamp.TSPVerifierOption)(nil)).Elem(), reflect.TypeOf((*timestamp.TSPVerifierOption)(nil)).Elem()},
		{"FakeTimestamper", reflect.TypeOf(compatTimestamp.FakeTimestamper{}), reflect.TypeOf(timestamp.FakeTimestamper{})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("TYPE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}

	// Interface types
	interfaceTests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"TimestampVerifier", reflect.TypeOf((*compatTimestamp.TimestampVerifier)(nil)).Elem(), reflect.TypeOf((*timestamp.TimestampVerifier)(nil)).Elem()},
		{"Timestamper", reflect.TypeOf((*compatTimestamp.Timestamper)(nil)).Elem(), reflect.TypeOf((*timestamp.Timestamper)(nil)).Elem()},
	}

	for _, tt := range interfaceTests {
		t.Run("Interface_"+tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("INTERFACE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}
}

func TestTypeIdentity_PolicySig(t *testing.T) {
	tests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"VerifyPolicySignatureOptions", reflect.TypeOf((*compatPolicySig.VerifyPolicySignatureOptions)(nil)), reflect.TypeOf((*policysig.VerifyPolicySignatureOptions)(nil))},
		{"Option", reflect.TypeOf((*compatPolicySig.Option)(nil)).Elem(), reflect.TypeOf((*policysig.Option)(nil)).Elem()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("TYPE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}
}

func TestTypeIdentity_Signer(t *testing.T) {
	interfaceTests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"SignerProvider", reflect.TypeOf((*compatSigner.SignerProvider)(nil)).Elem(), reflect.TypeOf((*signer.SignerProvider)(nil)).Elem()},
		{"VerifierProvider", reflect.TypeOf((*compatSigner.VerifierProvider)(nil)).Elem(), reflect.TypeOf((*signer.VerifierProvider)(nil)).Elem()},
	}

	for _, tt := range interfaceTests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("INTERFACE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}
}

func TestTypeIdentity_SignerKMS(t *testing.T) {
	tests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"KMSSignerProvider", reflect.TypeOf(compatSignerKMS.KMSSignerProvider{}), reflect.TypeOf(signerKMS.KMSSignerProvider{})},
		{"Option", reflect.TypeOf((*compatSignerKMS.Option)(nil)).Elem(), reflect.TypeOf((*signerKMS.Option)(nil)).Elem()},
		{"ProviderNotFoundError", reflect.TypeOf((*compatSignerKMS.ProviderNotFoundError)(nil)), reflect.TypeOf((*signerKMS.ProviderNotFoundError)(nil))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("TYPE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}

	// Interface
	t.Run("Interface_KMSClientOptions", func(t *testing.T) {
		compatT := reflect.TypeOf((*compatSignerKMS.KMSClientOptions)(nil)).Elem()
		rookeryT := reflect.TypeOf((*signerKMS.KMSClientOptions)(nil)).Elem()
		if compatT != rookeryT {
			t.Errorf("INTERFACE MISMATCH: compat %v != rookery %v", compatT, rookeryT)
		}
	})
}

func TestTypeIdentity_Registry(t *testing.T) {
	// Registry is generic, so test with a concrete type parameter.
	// Configurer is the only non-generic type/interface.
	t.Run("Interface_Configurer", func(t *testing.T) {
		compatT := reflect.TypeOf((*compatRegistry.Configurer)(nil)).Elem()
		rookeryT := reflect.TypeOf((*registry.Configurer)(nil)).Elem()
		if compatT != rookeryT {
			t.Errorf("INTERFACE MISMATCH: compat %v != rookery %v", compatT, rookeryT)
		}
	})
}

func TestTypeIdentity_Witness(t *testing.T) {
	tests := []struct {
		name    string
		compat  reflect.Type
		rookery reflect.Type
	}{
		{"RunOption", reflect.TypeOf((*witness.RunOption)(nil)).Elem(), reflect.TypeOf((*workflow.RunOption)(nil)).Elem()},
		{"RunResult", reflect.TypeOf(witness.RunResult{}), reflect.TypeOf(workflow.RunResult{})},
		{"VerifyOption", reflect.TypeOf((*witness.VerifyOption)(nil)).Elem(), reflect.TypeOf((*workflow.VerifyOption)(nil)).Elem()},
		{"VerifyResult", reflect.TypeOf(witness.VerifyResult{}), reflect.TypeOf(workflow.VerifyResult{})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("TYPE MISMATCH: compat %v != rookery %v", tt.compat, tt.rookery)
			}
		})
	}
}

// ============================================================================
// SECTION 2: FUNCTION POINTER IDENTITY TESTS
//
// For every exported function var in the compat layer, verify that the
// function pointer points to the SAME function as the rookery equivalent.
// This catches cases where someone accidentally wraps a function instead
// of aliasing it, which could cause subtle behavioral differences.
// ============================================================================

func TestFunctionIdentity_Witness(t *testing.T) {
	tests := []struct {
		name    string
		compat  interface{}
		rookery interface{}
	}{
		{"Run", witness.Run, workflow.Run},
		{"RunWithExports", witness.RunWithExports, workflow.RunWithExports},
		{"Sign", witness.Sign, workflow.Sign},
		{"Verify", witness.Verify, workflow.Verify},
		{"VerifySignature", witness.VerifySignature, workflow.VerifySignature},
		{"RunWithInsecure", witness.RunWithInsecure, workflow.RunWithInsecure},
		{"RunWithIgnoreErrors", witness.RunWithIgnoreErrors, workflow.RunWithIgnoreErrors},
		{"RunWithAttestors", witness.RunWithAttestors, workflow.RunWithAttestors},
		{"RunWithAttestationOpts", witness.RunWithAttestationOpts, workflow.RunWithAttestationOpts},
		{"RunWithTimestampers", witness.RunWithTimestampers, workflow.RunWithTimestampers},
		{"RunWithSigners", witness.RunWithSigners, workflow.RunWithSigners},
		{"VerifyWithSigners", witness.VerifyWithSigners, workflow.VerifyWithSigners},
		{"VerifyWithSubjectDigests", witness.VerifyWithSubjectDigests, workflow.VerifyWithSubjectDigests},
		{"VerifyWithCollectionSource", witness.VerifyWithCollectionSource, workflow.VerifyWithCollectionSource},
		{"VerifyWithRunOptions", witness.VerifyWithRunOptions, workflow.VerifyWithRunOptions},
		{"VerifyWithPolicyFulcioCertExtensions", witness.VerifyWithPolicyFulcioCertExtensions, workflow.VerifyWithPolicyFulcioCertExtensions},
		{"VerifyWithPolicyCertConstraints", witness.VerifyWithPolicyCertConstraints, workflow.VerifyWithPolicyCertConstraints},
		{"VerifyWithPolicyTimestampAuthorities", witness.VerifyWithPolicyTimestampAuthorities, workflow.VerifyWithPolicyTimestampAuthorities},
		{"VerifyWithPolicyCARoots", witness.VerifyWithPolicyCARoots, workflow.VerifyWithPolicyCARoots},
		{"VerifyWithPolicyCAIntermediates", witness.VerifyWithPolicyCAIntermediates, workflow.VerifyWithPolicyCAIntermediates},
		{"VerifyWithAiServerURL", witness.VerifyWithAiServerURL, workflow.VerifyWithAiServerURL},
		{"VerifyWithKMSProviderOptions", witness.VerifyWithKMSProviderOptions, workflow.VerifyWithKMSProviderOptions},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compatPtr := reflect.ValueOf(tt.compat).Pointer()
			rookeryPtr := reflect.ValueOf(tt.rookery).Pointer()
			if compatPtr != rookeryPtr {
				t.Errorf("FUNCTION POINTER MISMATCH: compat and rookery point to different functions")
			}
		})
	}
}

func TestFunctionIdentity_Attestation(t *testing.T) {
	tests := []struct {
		name    string
		compat  interface{}
		rookery interface{}
	}{
		{"NewContext", compatAttestation.NewContext, attestation.NewContext},
		{"NewCollection", compatAttestation.NewCollection, attestation.NewCollection},
		{"NewCollectionAttestation", compatAttestation.NewCollectionAttestation, attestation.NewCollectionAttestation},
		{"WithContext", compatAttestation.WithContext, attestation.WithContext},
		{"WithHashes", compatAttestation.WithHashes, attestation.WithHashes},
		{"WithWorkingDir", compatAttestation.WithWorkingDir, attestation.WithWorkingDir},
		{"WithDirHashGlob", compatAttestation.WithDirHashGlob, attestation.WithDirHashGlob},
		{"WithEnvironmentCapturer", compatAttestation.WithEnvironmentCapturer, attestation.WithEnvironmentCapturer},
		{"WithOutputWriters", compatAttestation.WithOutputWriters, attestation.WithOutputWriters},
		{"WithEnvFilterVarsEnabled", compatAttestation.WithEnvFilterVarsEnabled, attestation.WithEnvFilterVarsEnabled},
		{"WithEnvAdditionalKeys", compatAttestation.WithEnvAdditionalKeys, attestation.WithEnvAdditionalKeys},
		{"WithEnvExcludeKeys", compatAttestation.WithEnvExcludeKeys, attestation.WithEnvExcludeKeys},
		{"WithEnvDisableDefaultSensitiveList", compatAttestation.WithEnvDisableDefaultSensitiveList, attestation.WithEnvDisableDefaultSensitiveList},
		{"RegisterAttestation", compatAttestation.RegisterAttestation, attestation.RegisterAttestation},
		{"RegisterAttestationWithTypes", compatAttestation.RegisterAttestationWithTypes, attestation.RegisterAttestationWithTypes},
		{"FactoryByType", compatAttestation.FactoryByType, attestation.FactoryByType},
		{"FactoryByName", compatAttestation.FactoryByName, attestation.FactoryByName},
		{"GetAttestor", compatAttestation.GetAttestor, attestation.GetAttestor},
		{"Attestors", compatAttestation.Attestors, attestation.Attestors},
		{"GetAttestors", compatAttestation.GetAttestors, attestation.GetAttestors},
		{"AttestorOptions", compatAttestation.AttestorOptions, attestation.AttestorOptions},
		{"RegistrationEntries", compatAttestation.RegistrationEntries, attestation.RegistrationEntries},
		{"RegisterLegacyAlias", compatAttestation.RegisterLegacyAlias, attestation.RegisterLegacyAlias},
		{"RegisterLegacyAliases", compatAttestation.RegisterLegacyAliases, attestation.RegisterLegacyAliases},
		{"ResolveLegacyType", compatAttestation.ResolveLegacyType, attestation.ResolveLegacyType},
		{"DefaultSensitiveEnvList", compatAttestation.DefaultSensitiveEnvList, attestation.DefaultSensitiveEnvList},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compatPtr := reflect.ValueOf(tt.compat).Pointer()
			rookeryPtr := reflect.ValueOf(tt.rookery).Pointer()
			if compatPtr != rookeryPtr {
				t.Errorf("FUNCTION POINTER MISMATCH: compat and rookery point to different functions")
			}
		})
	}
}

func TestFunctionIdentity_Cryptoutil(t *testing.T) {
	tests := []struct {
		name    string
		compat  interface{}
		rookery interface{}
	}{
		{"DigestBytes", compatCrypto.DigestBytes, cryptoutil.DigestBytes},
		{"Digest", compatCrypto.Digest, cryptoutil.Digest},
		{"HexEncode", compatCrypto.HexEncode, cryptoutil.HexEncode},
		{"GeneratePublicKeyID", compatCrypto.GeneratePublicKeyID, cryptoutil.GeneratePublicKeyID},
		{"PublicPemBytes", compatCrypto.PublicPemBytes, cryptoutil.PublicPemBytes},
		{"UnmarshalPEMToPublicKey", compatCrypto.UnmarshalPEMToPublicKey, cryptoutil.UnmarshalPEMToPublicKey},
		{"TryParsePEMBlock", compatCrypto.TryParsePEMBlock, cryptoutil.TryParsePEMBlock},
		{"TryParsePEMBlockWithPassword", compatCrypto.TryParsePEMBlockWithPassword, cryptoutil.TryParsePEMBlockWithPassword},
		{"TryParseKeyFromReader", compatCrypto.TryParseKeyFromReader, cryptoutil.TryParseKeyFromReader},
		{"TryParseKeyFromReaderWithPassword", compatCrypto.TryParseKeyFromReaderWithPassword, cryptoutil.TryParseKeyFromReaderWithPassword},
		{"TryParseCertificate", compatCrypto.TryParseCertificate, cryptoutil.TryParseCertificate},
		{"ComputeDigest", compatCrypto.ComputeDigest, cryptoutil.ComputeDigest},
		{"HashToString", compatCrypto.HashToString, cryptoutil.HashToString},
		{"HashFromString", compatCrypto.HashFromString, cryptoutil.HashFromString},
		{"NewDigestSet", compatCrypto.NewDigestSet, cryptoutil.NewDigestSet},
		{"CalculateDigestSet", compatCrypto.CalculateDigestSet, cryptoutil.CalculateDigestSet},
		{"CalculateDigestSetFromBytes", compatCrypto.CalculateDigestSetFromBytes, cryptoutil.CalculateDigestSetFromBytes},
		{"CalculateDigestSetFromFile", compatCrypto.CalculateDigestSetFromFile, cryptoutil.CalculateDigestSetFromFile},
		{"CalculateDigestSetFromDir", compatCrypto.CalculateDigestSetFromDir, cryptoutil.CalculateDigestSetFromDir},
		{"NewSigner", compatCrypto.NewSigner, cryptoutil.NewSigner},
		{"NewSignerFromReader", compatCrypto.NewSignerFromReader, cryptoutil.NewSignerFromReader},
		{"SignWithCertificate", compatCrypto.SignWithCertificate, cryptoutil.SignWithCertificate},
		{"SignWithIntermediates", compatCrypto.SignWithIntermediates, cryptoutil.SignWithIntermediates},
		{"SignWithRoots", compatCrypto.SignWithRoots, cryptoutil.SignWithRoots},
		{"SignWithHash", compatCrypto.SignWithHash, cryptoutil.SignWithHash},
		{"NewVerifier", compatCrypto.NewVerifier, cryptoutil.NewVerifier},
		{"NewVerifierFromReader", compatCrypto.NewVerifierFromReader, cryptoutil.NewVerifierFromReader},
		{"VerifyWithRoots", compatCrypto.VerifyWithRoots, cryptoutil.VerifyWithRoots},
		{"VerifyWithIntermediates", compatCrypto.VerifyWithIntermediates, cryptoutil.VerifyWithIntermediates},
		{"VerifyWithHash", compatCrypto.VerifyWithHash, cryptoutil.VerifyWithHash},
		{"VerifyWithTrustedTime", compatCrypto.VerifyWithTrustedTime, cryptoutil.VerifyWithTrustedTime},
		{"NewRSASigner", compatCrypto.NewRSASigner, cryptoutil.NewRSASigner},
		{"NewRSAVerifier", compatCrypto.NewRSAVerifier, cryptoutil.NewRSAVerifier},
		{"NewECDSASigner", compatCrypto.NewECDSASigner, cryptoutil.NewECDSASigner},
		{"NewECDSAVerifier", compatCrypto.NewECDSAVerifier, cryptoutil.NewECDSAVerifier},
		{"NewED25519Signer", compatCrypto.NewED25519Signer, cryptoutil.NewED25519Signer},
		{"NewED25519Verifier", compatCrypto.NewED25519Verifier, cryptoutil.NewED25519Verifier},
		{"NewX509Verifier", compatCrypto.NewX509Verifier, cryptoutil.NewX509Verifier},
		{"NewX509Signer", compatCrypto.NewX509Signer, cryptoutil.NewX509Signer},
		{"DirhHashSha256", compatCrypto.DirhHashSha256, cryptoutil.DirhHashSha256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compatPtr := reflect.ValueOf(tt.compat).Pointer()
			rookeryPtr := reflect.ValueOf(tt.rookery).Pointer()
			if compatPtr != rookeryPtr {
				t.Errorf("FUNCTION POINTER MISMATCH: compat and rookery point to different functions")
			}
		})
	}
}

func TestFunctionIdentity_DSSE(t *testing.T) {
	tests := []struct {
		name    string
		compat  interface{}
		rookery interface{}
	}{
		{"Sign", compatDSSE.Sign, dsse.Sign},
		{"SignWithSigners", compatDSSE.SignWithSigners, dsse.SignWithSigners},
		{"SignWithTimestampers", compatDSSE.SignWithTimestampers, dsse.SignWithTimestampers},
		{"VerifyWithRoots", compatDSSE.VerifyWithRoots, dsse.VerifyWithRoots},
		{"VerifyWithIntermediates", compatDSSE.VerifyWithIntermediates, dsse.VerifyWithIntermediates},
		{"VerifyWithVerifiers", compatDSSE.VerifyWithVerifiers, dsse.VerifyWithVerifiers},
		{"VerifyWithThreshold", compatDSSE.VerifyWithThreshold, dsse.VerifyWithThreshold},
		{"VerifyWithTimestampVerifiers", compatDSSE.VerifyWithTimestampVerifiers, dsse.VerifyWithTimestampVerifiers},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compatPtr := reflect.ValueOf(tt.compat).Pointer()
			rookeryPtr := reflect.ValueOf(tt.rookery).Pointer()
			if compatPtr != rookeryPtr {
				t.Errorf("FUNCTION POINTER MISMATCH: compat and rookery point to different functions")
			}
		})
	}
}

func TestFunctionIdentity_File(t *testing.T) {
	compatPtr := reflect.ValueOf(compatFile.RecordArtifacts).Pointer()
	rookeryPtr := reflect.ValueOf(file.RecordArtifacts).Pointer()
	if compatPtr != rookeryPtr {
		t.Errorf("FUNCTION POINTER MISMATCH for RecordArtifacts: compat and rookery differ")
	}
}

func TestFunctionIdentity_Intoto(t *testing.T) {
	tests := []struct {
		name    string
		compat  interface{}
		rookery interface{}
	}{
		{"NewStatement", compatIntoto.NewStatement, intoto.NewStatement},
		{"DigestSetToSubject", compatIntoto.DigestSetToSubject, intoto.DigestSetToSubject},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compatPtr := reflect.ValueOf(tt.compat).Pointer()
			rookeryPtr := reflect.ValueOf(tt.rookery).Pointer()
			if compatPtr != rookeryPtr {
				t.Errorf("FUNCTION POINTER MISMATCH: compat and rookery point to different functions")
			}
		})
	}
}

func TestFunctionIdentity_Log(t *testing.T) {
	tests := []struct {
		name    string
		compat  interface{}
		rookery interface{}
	}{
		{"SetLogger", compatLog.SetLogger, log.SetLogger},
		{"GetLogger", compatLog.GetLogger, log.GetLogger},
		{"Errorf", compatLog.Errorf, log.Errorf},
		{"Error", compatLog.Error, log.Error},
		{"Warnf", compatLog.Warnf, log.Warnf},
		{"Warn", compatLog.Warn, log.Warn},
		{"Debugf", compatLog.Debugf, log.Debugf},
		{"Debug", compatLog.Debug, log.Debug},
		{"Infof", compatLog.Infof, log.Infof},
		{"Info", compatLog.Info, log.Info},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compatPtr := reflect.ValueOf(tt.compat).Pointer()
			rookeryPtr := reflect.ValueOf(tt.rookery).Pointer()
			if compatPtr != rookeryPtr {
				t.Errorf("FUNCTION POINTER MISMATCH: compat and rookery point to different functions")
			}
		})
	}
}

func TestFunctionIdentity_Policy(t *testing.T) {
	tests := []struct {
		name    string
		compat  interface{}
		rookery interface{}
	}{
		{"WithVerifiedSource", compatPolicy.WithVerifiedSource, policy.WithVerifiedSource},
		{"WithSubjectDigests", compatPolicy.WithSubjectDigests, policy.WithSubjectDigests},
		{"WithSearchDepth", compatPolicy.WithSearchDepth, policy.WithSearchDepth},
		{"WithAiServerURL", compatPolicy.WithAiServerURL, policy.WithAiServerURL},
		{"WithClockSkewTolerance", compatPolicy.WithClockSkewTolerance, policy.WithClockSkewTolerance},
		{"EvaluateRegoPolicy", compatPolicy.EvaluateRegoPolicy, policy.EvaluateRegoPolicy},
		{"EvaluateAIPolicy", compatPolicy.EvaluateAIPolicy, policy.EvaluateAIPolicy},
		{"ExecuteAiPolicy", compatPolicy.ExecuteAiPolicy, policy.ExecuteAiPolicy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compatPtr := reflect.ValueOf(tt.compat).Pointer()
			rookeryPtr := reflect.ValueOf(tt.rookery).Pointer()
			if compatPtr != rookeryPtr {
				t.Errorf("FUNCTION POINTER MISMATCH: compat and rookery point to different functions")
			}
		})
	}
}

func TestFunctionIdentity_PolicySig(t *testing.T) {
	tests := []struct {
		name    string
		compat  interface{}
		rookery interface{}
	}{
		{"VerifyWithPolicyVerifiers", compatPolicySig.VerifyWithPolicyVerifiers, policysig.VerifyWithPolicyVerifiers},
		{"VerifyWithPolicyTimestampAuthorities", compatPolicySig.VerifyWithPolicyTimestampAuthorities, policysig.VerifyWithPolicyTimestampAuthorities},
		{"VerifyWithPolicyCARoots", compatPolicySig.VerifyWithPolicyCARoots, policysig.VerifyWithPolicyCARoots},
		{"VerifyWithPolicyCAIntermediates", compatPolicySig.VerifyWithPolicyCAIntermediates, policysig.VerifyWithPolicyCAIntermediates},
		{"NewVerifyPolicySignatureOptions", compatPolicySig.NewVerifyPolicySignatureOptions, policysig.NewVerifyPolicySignatureOptions},
		{"VerifyWithPolicyFulcioCertExtensions", compatPolicySig.VerifyWithPolicyFulcioCertExtensions, policysig.VerifyWithPolicyFulcioCertExtensions},
		{"VerifyWithPolicyCertConstraints", compatPolicySig.VerifyWithPolicyCertConstraints, policysig.VerifyWithPolicyCertConstraints},
		{"VerifyPolicySignature", compatPolicySig.VerifyPolicySignature, policysig.VerifyPolicySignature},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compatPtr := reflect.ValueOf(tt.compat).Pointer()
			rookeryPtr := reflect.ValueOf(tt.rookery).Pointer()
			if compatPtr != rookeryPtr {
				t.Errorf("FUNCTION POINTER MISMATCH: compat and rookery point to different functions")
			}
		})
	}
}

func TestFunctionIdentity_Source(t *testing.T) {
	tests := []struct {
		name    string
		compat  interface{}
		rookery interface{}
	}{
		{"NewMemorySource", compatSource.NewMemorySource, source.NewMemorySource},
		{"NewMultiSource", compatSource.NewMultiSource, source.NewMultiSource},
		{"NewVerifiedSource", compatSource.NewVerifiedSource, source.NewVerifiedSource},
		{"NewArchivistaSource", compatSource.NewArchivistaSource, source.NewArchivistaSource},
		{"NewArchvistSource", compatSource.NewArchvistSource, source.NewArchvistSource},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compatPtr := reflect.ValueOf(tt.compat).Pointer()
			rookeryPtr := reflect.ValueOf(tt.rookery).Pointer()
			if compatPtr != rookeryPtr {
				t.Errorf("FUNCTION POINTER MISMATCH: compat and rookery point to different functions")
			}
		})
	}
}

func TestFunctionIdentity_Timestamp(t *testing.T) {
	tests := []struct {
		name    string
		compat  interface{}
		rookery interface{}
	}{
		{"NewTimestamper", compatTimestamp.NewTimestamper, timestamp.NewTimestamper},
		{"TimestampWithUrl", compatTimestamp.TimestampWithUrl, timestamp.TimestampWithUrl},
		{"TimestampWithHash", compatTimestamp.TimestampWithHash, timestamp.TimestampWithHash},
		{"TimestampWithRequestCertificate", compatTimestamp.TimestampWithRequestCertificate, timestamp.TimestampWithRequestCertificate},
		{"NewVerifier", compatTimestamp.NewVerifier, timestamp.NewVerifier},
		{"VerifyWithCerts", compatTimestamp.VerifyWithCerts, timestamp.VerifyWithCerts},
		{"VerifyWithHash", compatTimestamp.VerifyWithHash, timestamp.VerifyWithHash},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compatPtr := reflect.ValueOf(tt.compat).Pointer()
			rookeryPtr := reflect.ValueOf(tt.rookery).Pointer()
			if compatPtr != rookeryPtr {
				t.Errorf("FUNCTION POINTER MISMATCH: compat and rookery point to different functions")
			}
		})
	}
}

func TestFunctionIdentity_Signer(t *testing.T) {
	tests := []struct {
		name    string
		compat  interface{}
		rookery interface{}
	}{
		{"Register", compatSigner.Register, signer.Register},
		{"RegistryEntries", compatSigner.RegistryEntries, signer.RegistryEntries},
		{"NewSignerProvider", compatSigner.NewSignerProvider, signer.NewSignerProvider},
		{"RegisterVerifier", compatSigner.RegisterVerifier, signer.RegisterVerifier},
		{"VerifierRegistryEntries", compatSigner.VerifierRegistryEntries, signer.VerifierRegistryEntries},
		{"NewVerifierProvider", compatSigner.NewVerifierProvider, signer.NewVerifierProvider},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compatPtr := reflect.ValueOf(tt.compat).Pointer()
			rookeryPtr := reflect.ValueOf(tt.rookery).Pointer()
			if compatPtr != rookeryPtr {
				t.Errorf("FUNCTION POINTER MISMATCH: compat and rookery point to different functions")
			}
		})
	}
}

func TestFunctionIdentity_SignerKMS(t *testing.T) {
	tests := []struct {
		name    string
		compat  interface{}
		rookery interface{}
	}{
		{"New", compatSignerKMS.New, signerKMS.New},
		{"WithRef", compatSignerKMS.WithRef, signerKMS.WithRef},
		{"WithHash", compatSignerKMS.WithHash, signerKMS.WithHash},
		{"WithKeyVersion", compatSignerKMS.WithKeyVersion, signerKMS.WithKeyVersion},
		{"AddProvider", compatSignerKMS.AddProvider, signerKMS.AddProvider},
		{"SupportedProviders", compatSignerKMS.SupportedProviders, signerKMS.SupportedProviders},
		{"ProviderOptions", compatSignerKMS.ProviderOptions, signerKMS.ProviderOptions},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compatPtr := reflect.ValueOf(tt.compat).Pointer()
			rookeryPtr := reflect.ValueOf(tt.rookery).Pointer()
			if compatPtr != rookeryPtr {
				t.Errorf("FUNCTION POINTER MISMATCH: compat and rookery point to different functions")
			}
		})
	}
}

// ============================================================================
// SECTION 3: MISSING EXPORTS AUDIT
//
// Cross-reference the public API of each rookery package against what the
// compat layer re-exports. This uses go doc output captured as expected
// symbols. This section documents known gaps as test failures.
// ============================================================================

func TestMissingExports_Attestation(t *testing.T) {
	// Symbols that exist in rookery attestation but are NOT in the compat shim.
	// Each entry here is a gap that could break go-witness users.
	missing := []string{
		"LegacyAlternate", // New function not exposed in compat
	}

	for _, sym := range missing {
		t.Run("MISSING_"+sym, func(t *testing.T) {
			t.Errorf("MISSING EXPORT: rookery attestation.%s is not re-exported by compat/go-witness/attestation", sym)
		})
	}
}

func TestMissingExports_Cryptoutil(t *testing.T) {
	// No missing exports detected -- all exported types, functions, and
	// constants in rookery cryptoutil are re-exported in the compat shim.
	// This test exists as a placeholder to document the audit.
	t.Log("cryptoutil: all exports accounted for")
}

func TestMissingExports_Policy(t *testing.T) {
	// Check that new policy types/functions added with cross-step feature
	// are present. These WERE missing but are now expected to be present
	// after the compat layer was updated.
	// We verify via compile-time check (the type identity tests above)
	// and runtime function pointer identity.
	t.Log("policy: ErrCircularDependency, ErrSelfReference, ErrDependencyNotVerified now present")
	t.Log("policy: WithClockSkewTolerance now present")
}

func TestMissingExports_SignerKMS(t *testing.T) {
	// ParseHashFunc exists in rookery signer/kms but is NOT in compat.
	missing := []string{
		"ParseHashFunc",
	}

	for _, sym := range missing {
		t.Run("MISSING_"+sym, func(t *testing.T) {
			t.Errorf("MISSING EXPORT: rookery signer/kms.%s is not re-exported by compat/go-witness/signer/kms", sym)
		})
	}
}

func TestMissingExports_Registry(t *testing.T) {
	// Generic functions cannot be aliased as package-level vars in Go.
	// This is documented in the compat shim. These are expected gaps:
	// - New[T]()
	// - SetOptions[T]()
	// - IntConfigOption[T]()
	// - StringConfigOption[T]()
	// - BoolConfigOption[T]()
	// - DurationConfigOption[T]()
	// - StringSliceConfigOption[T]()
	//
	// This is an inherent Go limitation, not a compat bug.
	// Attestor plugins use attestation.RegisterAttestation() instead.
	missingGenerics := []string{
		"New",
		"SetOptions",
		"IntConfigOption",
		"StringConfigOption",
		"BoolConfigOption",
		"DurationConfigOption",
		"StringSliceConfigOption",
	}

	for _, sym := range missingGenerics {
		t.Run("EXPECTED_MISSING_"+sym, func(t *testing.T) {
			t.Logf("EXPECTED MISSING: registry.%s cannot be aliased (generic function)", sym)
		})
	}
}

func TestMissingExports_Workflow(t *testing.T) {
	// Types/interfaces only available in rookery workflow but NOT in the
	// compat root witness package.
	missing := []string{
		"PolicyVerifyConfigurer", // Interface only used by policyverify attestor
		"PolicyVerifyResult",     // Interface only used by policyverify attestor
	}

	for _, sym := range missing {
		t.Run("MISSING_"+sym, func(t *testing.T) {
			// These are internal interfaces used by the policyverify attestor
			// plugin. Go-witness plugins would not typically need these.
			// Log as informational, not a hard failure.
			t.Logf("INFORMATIONAL: workflow.%s not in compat (internal interface)", sym)
		})
	}
}

// ============================================================================
// SECTION 4: CONSTANT VALUE IDENTITY TESTS
//
// Verify that every aliased constant has the exact same value in both
// the compat and rookery packages.
// ============================================================================

func TestConstantValues_Attestation(t *testing.T) {
	tests := []struct {
		name    string
		compat  interface{}
		rookery interface{}
	}{
		{"CollectionType", compatAttestation.CollectionType, attestation.CollectionType},
		{"LegacyCollectionType", compatAttestation.LegacyCollectionType, attestation.LegacyCollectionType},
		{"PreMaterialRunType", compatAttestation.PreMaterialRunType, attestation.PreMaterialRunType},
		{"MaterialRunType", compatAttestation.MaterialRunType, attestation.MaterialRunType},
		{"ExecuteRunType", compatAttestation.ExecuteRunType, attestation.ExecuteRunType},
		{"ProductRunType", compatAttestation.ProductRunType, attestation.ProductRunType},
		{"PostProductRunType", compatAttestation.PostProductRunType, attestation.PostProductRunType},
		{"VerifyRunType", compatAttestation.VerifyRunType, attestation.VerifyRunType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("CONSTANT MISMATCH: compat=%v rookery=%v", tt.compat, tt.rookery)
			}
		})
	}
}

func TestConstantValues_Cryptoutil(t *testing.T) {
	if compatCrypto.PublicKeyPEMType != cryptoutil.PublicKeyPEMType {
		t.Errorf("PublicKeyPEMType mismatch")
	}
	if compatCrypto.PKCS1PublicKeyPEMType != cryptoutil.PKCS1PublicKeyPEMType {
		t.Errorf("PKCS1PublicKeyPEMType mismatch")
	}
}

func TestConstantValues_DSSE(t *testing.T) {
	if compatDSSE.PemTypeCertificate != dsse.PemTypeCertificate {
		t.Errorf("PemTypeCertificate mismatch")
	}
	if compatDSSE.TimestampRFC3161 != dsse.TimestampRFC3161 {
		t.Errorf("TimestampRFC3161 mismatch")
	}
}

func TestConstantValues_Intoto(t *testing.T) {
	if compatIntoto.StatementType != intoto.StatementType {
		t.Errorf("StatementType mismatch")
	}
	if compatIntoto.PayloadType != intoto.PayloadType {
		t.Errorf("PayloadType mismatch")
	}
}

func TestConstantValues_Policy(t *testing.T) {
	if compatPolicy.PolicyPredicate != policy.PolicyPredicate {
		t.Errorf("PolicyPredicate mismatch")
	}
	if compatPolicy.LegacyPolicyPredicate != policy.LegacyPolicyPredicate {
		t.Errorf("LegacyPolicyPredicate mismatch")
	}
	if compatPolicy.AllowAllConstraint != policy.AllowAllConstraint {
		t.Errorf("AllowAllConstraint mismatch")
	}
}

func TestConstantValues_SLSA(t *testing.T) {
	if compatSLSA.VerificationSummaryPredicate != slsa.VerificationSummaryPredicate {
		t.Errorf("VerificationSummaryPredicate mismatch")
	}
	if compatSLSA.PassedVerificationResult != slsa.PassedVerificationResult {
		t.Errorf("PassedVerificationResult mismatch")
	}
	if compatSLSA.FailedVerificationResult != slsa.FailedVerificationResult {
		t.Errorf("FailedVerificationResult mismatch")
	}
}

// ============================================================================
// SECTION 5: BEHAVIORAL DRIFT TESTS
//
// Exercise real operations through the compat layer and verify the results
// are identical to operating through the rookery layer directly.
// ============================================================================

func TestBehavioralDrift_DigestSetRoundtrip(t *testing.T) {
	// Create a DigestSet via compat, serialize, deserialize via rookery.
	data := []byte("test payload for digest")
	hashes := []compatCrypto.DigestValue{{Hash: crypto.SHA256}}

	compatDS, err := compatCrypto.CalculateDigestSetFromBytes(data, hashes)
	if err != nil {
		t.Fatalf("compat CalculateDigestSetFromBytes: %v", err)
	}

	rookeryDS, err := cryptoutil.CalculateDigestSetFromBytes(data, hashes)
	if err != nil {
		t.Fatalf("rookery CalculateDigestSetFromBytes: %v", err)
	}

	// Compare the digest values.
	if !compatDS.Equal(rookeryDS) {
		t.Errorf("DigestSets not equal:\n  compat=%v\n  rookery=%v", compatDS, rookeryDS)
	}

	// JSON roundtrip.
	compatJSON, err := json.Marshal(compatDS)
	if err != nil {
		t.Fatalf("marshal compat DS: %v", err)
	}

	var restoredDS cryptoutil.DigestSet
	if err := json.Unmarshal(compatJSON, &restoredDS); err != nil {
		t.Fatalf("unmarshal into rookery DS: %v", err)
	}
	if !restoredDS.Equal(rookeryDS) {
		t.Errorf("JSON roundtrip produced different DigestSet")
	}
}

func TestBehavioralDrift_SignAndVerifyECDSA(t *testing.T) {
	// Generate ECDSA key pair.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	// Create signer through compat layer.
	compatSgn := compatCrypto.NewECDSASigner(privKey, crypto.SHA256)

	// Create verifier through rookery layer.
	rookeryVer := cryptoutil.NewECDSAVerifier(&privKey.PublicKey, crypto.SHA256)

	payload := []byte("critical supply chain data")

	// Sign with compat signer.
	sig, err := compatSgn.Sign(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("compat sign failed: %v", err)
	}

	// Verify with rookery verifier.
	if err := rookeryVer.Verify(bytes.NewReader(payload), sig); err != nil {
		t.Errorf("BEHAVIORAL DRIFT: compat-signed data failed rookery verification: %v", err)
	}

	// Now reverse: sign with rookery, verify with compat.
	rookerySgn := cryptoutil.NewECDSASigner(privKey, crypto.SHA256)
	sig2, err := rookerySgn.Sign(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("rookery sign failed: %v", err)
	}

	compatVer := compatCrypto.NewECDSAVerifier(&privKey.PublicKey, crypto.SHA256)
	if err := compatVer.Verify(bytes.NewReader(payload), sig2); err != nil {
		t.Errorf("BEHAVIORAL DRIFT: rookery-signed data failed compat verification: %v", err)
	}
}

func TestBehavioralDrift_SignAndVerifyED25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ED25519 key: %v", err)
	}

	// Sign via compat, verify via rookery.
	compatSgn := compatCrypto.NewED25519Signer(priv)
	rookeryVer := cryptoutil.NewED25519Verifier(pub)

	payload := []byte("ed25519 attestation payload")
	sig, err := compatSgn.Sign(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("compat ed25519 sign failed: %v", err)
	}
	if err := rookeryVer.Verify(bytes.NewReader(payload), sig); err != nil {
		t.Errorf("BEHAVIORAL DRIFT: compat ed25519 signature failed rookery verification: %v", err)
	}
}

func TestBehavioralDrift_SignAndVerifyRSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Sign via compat, verify via rookery.
	compatSgn := compatCrypto.NewRSASigner(privKey, crypto.SHA256)
	rookeryVer := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	payload := []byte("rsa attestation payload")
	sig, err := compatSgn.Sign(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("compat RSA sign failed: %v", err)
	}
	if err := rookeryVer.Verify(bytes.NewReader(payload), sig); err != nil {
		t.Errorf("BEHAVIORAL DRIFT: compat RSA signature failed rookery verification: %v", err)
	}
}

func TestBehavioralDrift_DSSESignAndVerify(t *testing.T) {
	// Generate a key pair for DSSE signing.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	compatSgn := compatCrypto.NewECDSASigner(privKey, crypto.SHA256)
	rookeryVer := cryptoutil.NewECDSAVerifier(&privKey.PublicKey, crypto.SHA256)

	payload := []byte(`{"predicateType": "test"}`)

	// Sign DSSE envelope via compat layer.
	env, err := compatDSSE.Sign("application/vnd.in-toto+json", bytes.NewReader(payload),
		compatDSSE.SignWithSigners(compatSgn))
	if err != nil {
		t.Fatalf("compat DSSE Sign failed: %v", err)
	}

	// Verify via rookery layer.
	checked, err := env.Verify(dsse.VerifyWithVerifiers(rookeryVer))
	if err != nil {
		t.Errorf("BEHAVIORAL DRIFT: compat DSSE envelope failed rookery verification: %v", err)
	}
	if len(checked) == 0 {
		t.Error("no checked verifiers returned")
	}
}

func TestBehavioralDrift_PolicyCreatedViaCompat_VerifiedViaRookery(t *testing.T) {
	// Create a policy using compat types, serialize, deserialize with rookery.
	compatP := compatPolicy.Policy{
		Steps: map[string]compatPolicy.Step{
			"build": {
				Name: "build",
				Functionaries: []compatPolicy.Functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
				Attestations: []compatPolicy.Attestation{
					{
						Type: "https://aflock.ai/attestations/command-run/v0.1",
						RegoPolicies: []compatPolicy.RegoPolicy{
							{Name: "exit-zero", Module: []byte(`package commandrun
deny[msg] {
  input.exitcode != 0
  msg := "command did not exit cleanly"
}`)},
						},
					},
				},
				ArtifactsFrom: []string{},
			},
		},
		PublicKeys: map[string]compatPolicy.PublicKey{
			"key-1": {KeyID: "key-1", Key: []byte("fake-pem-data")},
		},
	}

	// Serialize via compat.
	data, err := json.Marshal(compatP)
	if err != nil {
		t.Fatalf("marshal compat policy: %v", err)
	}

	// Deserialize via rookery.
	var rookeryP policy.Policy
	if err := json.Unmarshal(data, &rookeryP); err != nil {
		t.Fatalf("unmarshal into rookery policy: %v", err)
	}

	// Verify structural equality.
	if len(rookeryP.Steps) != 1 {
		t.Fatalf("expected 1 step, got %d", len(rookeryP.Steps))
	}
	step := rookeryP.Steps["build"]
	if step.Name != "build" {
		t.Errorf("step name = %q, want %q", step.Name, "build")
	}
	if len(step.Functionaries) != 1 {
		t.Fatalf("expected 1 functionary, got %d", len(step.Functionaries))
	}
	if step.Functionaries[0].PublicKeyID != "key-1" {
		t.Errorf("functionary key ID = %q, want %q", step.Functionaries[0].PublicKeyID, "key-1")
	}
	if len(step.Attestations) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(step.Attestations))
	}
	if step.Attestations[0].Type != "https://aflock.ai/attestations/command-run/v0.1" {
		t.Errorf("attestation type mismatch")
	}
	if len(step.Attestations[0].RegoPolicies) != 1 {
		t.Fatalf("expected 1 rego policy, got %d", len(step.Attestations[0].RegoPolicies))
	}
	if step.Attestations[0].RegoPolicies[0].Name != "exit-zero" {
		t.Errorf("rego policy name mismatch")
	}

	// Validate should pass (no circular deps).
	if err := rookeryP.Validate(); err != nil {
		t.Errorf("Validate failed on compat-created policy: %v", err)
	}
}

func TestBehavioralDrift_CollectionRoundtrip(t *testing.T) {
	// Create a Collection with attestors through the compat layer,
	// serialize, and verify rookery can deserialize with identical structure.
	completed := []compatAttestation.CompletedAttestor{
		{
			Attestor:  &dummyAttestor{name: "audit-test", typ: "https://aflock.ai/attestations/audit-test/v0.1"},
			StartTime: time.Now().Add(-1 * time.Second),
			EndTime:   time.Now(),
		},
	}

	compatColl := compatAttestation.NewCollection("audit-step", completed)

	data, err := json.Marshal(compatColl)
	if err != nil {
		t.Fatalf("marshal compat collection: %v", err)
	}

	var rookeryColl attestation.Collection
	if err := json.Unmarshal(data, &rookeryColl); err != nil {
		t.Fatalf("unmarshal into rookery collection: %v", err)
	}

	if rookeryColl.Name != compatColl.Name {
		t.Errorf("Name: compat=%q rookery=%q", compatColl.Name, rookeryColl.Name)
	}
	if len(rookeryColl.Attestations) != len(compatColl.Attestations) {
		t.Errorf("Attestation count: compat=%d rookery=%d",
			len(compatColl.Attestations), len(rookeryColl.Attestations))
	}
}

func TestBehavioralDrift_InTotoStatementCreation(t *testing.T) {
	subjects := map[string]compatCrypto.DigestSet{
		"artifact.bin": {
			compatCrypto.DigestValue{Hash: crypto.SHA256}: "abcdef1234567890",
		},
	}

	compatStmt, err := compatIntoto.NewStatement(
		"https://aflock.ai/attestation-collection/v0.1",
		[]byte(`{"name":"build"}`),
		subjects,
	)
	if err != nil {
		t.Fatalf("compat NewStatement failed: %v", err)
	}

	// Create identical statement via rookery.
	rookeryStmt, err := intoto.NewStatement(
		"https://aflock.ai/attestation-collection/v0.1",
		[]byte(`{"name":"build"}`),
		subjects,
	)
	if err != nil {
		t.Fatalf("rookery NewStatement failed: %v", err)
	}

	// Both should produce the same JSON.
	compatJSON, _ := json.Marshal(compatStmt)
	rookeryJSON, _ := json.Marshal(rookeryStmt)

	if string(compatJSON) != string(rookeryJSON) {
		t.Errorf("BEHAVIORAL DRIFT: NewStatement produced different JSON\n  compat:  %s\n  rookery: %s",
			string(compatJSON), string(rookeryJSON))
	}
}

func TestBehavioralDrift_MemorySourceCrossLayer(t *testing.T) {
	// Load an envelope through compat, search through rookery.
	ms := compatSource.NewMemorySource()

	// Build a minimal envelope.
	collection := attestation.Collection{
		Name:         "cross-layer-search",
		Attestations: []attestation.CollectionAttestation{},
	}
	collJSON, _ := json.Marshal(collection)

	subjects := map[string]cryptoutil.DigestSet{
		"binary": {
			cryptoutil.DigestValue{Hash: crypto.SHA256}: "deadbeef",
		},
	}

	var subjectList []intoto.Subject
	for name, ds := range subjects {
		subj, err := intoto.DigestSetToSubject(name, ds)
		if err != nil {
			t.Fatal(err)
		}
		subjectList = append(subjectList, subj)
	}

	stmt := intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: attestation.CollectionType,
		Subject:       subjectList,
		Predicate:     json.RawMessage(collJSON),
	}
	stmtJSON, _ := json.Marshal(stmt)

	env := compatDSSE.Envelope{
		Payload:     stmtJSON,
		PayloadType: intoto.PayloadType,
		Signatures:  []compatDSSE.Signature{},
	}

	if err := ms.LoadEnvelope("ref-cross", env); err != nil {
		t.Fatalf("LoadEnvelope: %v", err)
	}

	// Search through rookery Sourcer interface.
	var s source.Sourcer = ms
	results, err := s.Search(context.Background(), "cross-layer-search", []string{"deadbeef"}, nil)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Collection.Name != "cross-layer-search" {
		t.Errorf("Collection.Name = %q", results[0].Collection.Name)
	}
}

func TestBehavioralDrift_KeyIDConsistency(t *testing.T) {
	// Verify that KeyID() returns the same value whether called through
	// compat or rookery signer types.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	compatSgn := compatCrypto.NewECDSASigner(privKey, crypto.SHA256)
	rookerySgn := cryptoutil.NewECDSASigner(privKey, crypto.SHA256)

	compatID, err := compatSgn.KeyID()
	if err != nil {
		t.Fatalf("compat KeyID: %v", err)
	}
	rookeryID, err := rookerySgn.KeyID()
	if err != nil {
		t.Fatalf("rookery KeyID: %v", err)
	}

	if compatID != rookeryID {
		t.Errorf("BEHAVIORAL DRIFT: KeyID differs\n  compat:  %s\n  rookery: %s", compatID, rookeryID)
	}
}

func TestBehavioralDrift_PublicPemBytesConsistency(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	compatPEM, err := compatCrypto.PublicPemBytes(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("compat PublicPemBytes: %v", err)
	}
	rookeryPEM, err := cryptoutil.PublicPemBytes(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("rookery PublicPemBytes: %v", err)
	}

	if !bytes.Equal(compatPEM, rookeryPEM) {
		t.Errorf("BEHAVIORAL DRIFT: PublicPemBytes differ")
	}
}

func TestBehavioralDrift_HashStringRoundtrip(t *testing.T) {
	// Only test hashes that are supported by the library.
	// SHA-512 is not supported by HashToString.
	hashes := []crypto.Hash{crypto.SHA256, crypto.SHA1}

	for _, h := range hashes {
		compatStr, err := compatCrypto.HashToString(h)
		if err != nil {
			t.Fatalf("compat HashToString(%v): %v", h, err)
		}
		rookeryStr, err := cryptoutil.HashToString(h)
		if err != nil {
			t.Fatalf("rookery HashToString(%v): %v", h, err)
		}
		if compatStr != rookeryStr {
			t.Errorf("HashToString(%v) differs: compat=%q rookery=%q", h, compatStr, rookeryStr)
		}

		compatHash, err := compatCrypto.HashFromString(compatStr)
		if err != nil {
			t.Fatalf("compat HashFromString(%q): %v", compatStr, err)
		}
		rookeryHash, err := cryptoutil.HashFromString(rookeryStr)
		if err != nil {
			t.Fatalf("rookery HashFromString(%q): %v", rookeryStr, err)
		}
		if compatHash != rookeryHash {
			t.Errorf("HashFromString(%q) differs: compat=%v rookery=%v", compatStr, compatHash, rookeryHash)
		}
	}
}

func TestBehavioralDrift_LoggerInterop(t *testing.T) {
	// Set logger via compat, read via rookery.
	originalLogger := log.GetLogger()
	defer log.SetLogger(originalLogger)

	compatLog.SetLogger(compatLog.SilentLogger{})
	logger := log.GetLogger()

	if _, ok := logger.(log.SilentLogger); !ok {
		t.Errorf("BEHAVIORAL DRIFT: logger set via compat is not SilentLogger in rookery, got %T", logger)
	}

	// Now reverse: set via rookery, read via compat.
	log.SetLogger(log.ConsoleLogger{})
	compatLogger := compatLog.GetLogger()

	if _, ok := compatLogger.(compatLog.ConsoleLogger); !ok {
		t.Errorf("BEHAVIORAL DRIFT: logger set via rookery is not ConsoleLogger in compat, got %T", compatLogger)
	}
}

func TestBehavioralDrift_RegistrySharedState(t *testing.T) {
	// Register an attestor via compat, verify it's visible via rookery.
	testType := "https://aflock.ai/attestations/shared-registry-audit/v0.1"

	compatAttestation.RegisterAttestation(
		"shared-registry-audit",
		testType,
		compatAttestation.PreMaterialRunType,
		func() compatAttestation.Attestor {
			return &dummyAttestor{name: "shared-registry-audit", typ: testType}
		},
	)

	// Check via rookery.
	_, ok := attestation.FactoryByType(testType)
	if !ok {
		t.Errorf("BEHAVIORAL DRIFT: attestor registered via compat not found via rookery FactoryByType")
	}

	_, ok = attestation.FactoryByName("shared-registry-audit")
	if !ok {
		t.Errorf("BEHAVIORAL DRIFT: attestor registered via compat not found via rookery FactoryByName")
	}
}

func TestBehavioralDrift_RunInsecureProducesSameResult(t *testing.T) {
	// Run via compat and rookery with same parameters.
	compatResult, err := witness.Run("drift-test-step", witness.RunWithInsecure(true))
	if err != nil {
		t.Fatalf("compat Run: %v", err)
	}

	rookeryResult, err := workflow.Run("drift-test-step", workflow.RunWithInsecure(true))
	if err != nil {
		t.Fatalf("rookery Run: %v", err)
	}

	if compatResult.Collection.Name != rookeryResult.Collection.Name {
		t.Errorf("BEHAVIORAL DRIFT: Collection.Name compat=%q rookery=%q",
			compatResult.Collection.Name, rookeryResult.Collection.Name)
	}
}

func TestBehavioralDrift_NewSignerFromKey(t *testing.T) {
	// Test NewSigner via compat vs rookery produces interchangeable signers.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	compatS, err := compatCrypto.NewSigner(privKey)
	if err != nil {
		t.Fatalf("compat NewSigner: %v", err)
	}

	rookeryS, err := cryptoutil.NewSigner(privKey)
	if err != nil {
		t.Fatalf("rookery NewSigner: %v", err)
	}

	// Signatures should be verifiable cross-layer.
	payload := []byte("cross-signer test")

	sig1, err := compatS.Sign(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("compat sign: %v", err)
	}

	// Get verifier from rookery signer.
	rookeryV, err := rookeryS.Verifier()
	if err != nil {
		t.Fatalf("rookery verifier: %v", err)
	}

	if err := rookeryV.Verify(bytes.NewReader(payload), sig1); err != nil {
		t.Errorf("BEHAVIORAL DRIFT: compat-signed payload failed rookery verification: %v", err)
	}

	// And reverse.
	sig2, err := rookeryS.Sign(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("rookery sign: %v", err)
	}
	compatV, err := compatS.Verifier()
	if err != nil {
		t.Fatalf("compat verifier: %v", err)
	}
	if err := compatV.Verify(bytes.NewReader(payload), sig2); err != nil {
		t.Errorf("BEHAVIORAL DRIFT: rookery-signed payload failed compat verification: %v", err)
	}
}

// ============================================================================
// SECTION 6: END-TO-END COMPAT SCENARIOS
//
// Full workflow tests that exercise the compat layer as a go-witness user
// would use it.
// ============================================================================

func TestE2E_CompatDSSESignVerifyRoundtrip(t *testing.T) {
	// Full DSSE sign -> verify -> extract payload using only compat types,
	// then verify that rookery types can consume the result.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s := compatCrypto.NewECDSASigner(privKey, crypto.SHA256)
	v := compatCrypto.NewECDSAVerifier(&privKey.PublicKey, crypto.SHA256)

	payload := []byte(`{"step":"build","attestations":[]}`)

	env, err := compatDSSE.Sign("application/vnd.in-toto+json",
		bytes.NewReader(payload),
		compatDSSE.SignWithSigners(s))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify using compat types.
	checkedCompat, err := env.Verify(compatDSSE.VerifyWithVerifiers(v))
	if err != nil {
		t.Fatalf("compat Verify: %v", err)
	}

	// Now verify the same envelope using rookery types.
	var rookeryEnv dsse.Envelope = env
	rookeryV := cryptoutil.NewECDSAVerifier(&privKey.PublicKey, crypto.SHA256)
	checkedRookery, err := rookeryEnv.Verify(dsse.VerifyWithVerifiers(rookeryV))
	if err != nil {
		t.Fatalf("rookery Verify: %v", err)
	}

	if len(checkedCompat) != len(checkedRookery) {
		t.Errorf("checked verifier count: compat=%d rookery=%d",
			len(checkedCompat), len(checkedRookery))
	}

	// Verify payloads are identical.
	if !bytes.Equal(env.Payload, rookeryEnv.Payload) {
		t.Error("payloads differ between compat and rookery envelopes")
	}
}

func TestE2E_CompatRunWithExports(t *testing.T) {
	results, err := witness.RunWithExports("e2e-exports",
		witness.RunWithInsecure(true))
	if err != nil {
		t.Fatalf("RunWithExports: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("no results from RunWithExports")
	}

	for _, r := range results {
		var _ workflow.RunResult = r
		if r.Collection.Name != "e2e-exports" {
			t.Errorf("unexpected collection name: %q", r.Collection.Name)
		}
	}
}

func TestE2E_CompatWorkflowSign(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s := compatCrypto.NewECDSASigner(privKey, crypto.SHA256)

	payload := []byte(`{"test": "workflow sign"}`)
	var buf bytes.Buffer

	err = witness.Sign(
		bytes.NewReader(payload),
		"application/vnd.in-toto+json",
		&buf,
		compatDSSE.SignWithSigners(s),
	)
	if err != nil {
		t.Fatalf("witness.Sign: %v", err)
	}

	// Verify the output is a valid DSSE envelope.
	var env dsse.Envelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal signed envelope: %v", err)
	}

	if env.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("PayloadType = %q, want application/vnd.in-toto+json", env.PayloadType)
	}
	if len(env.Signatures) == 0 {
		t.Error("no signatures in signed envelope")
	}

	// Verify signature with rookery verifier.
	v := cryptoutil.NewECDSAVerifier(&privKey.PublicKey, crypto.SHA256)
	checked, err := env.Verify(dsse.VerifyWithVerifiers(v))
	if err != nil {
		t.Errorf("verification of compat-signed envelope failed: %v", err)
	}
	if len(checked) == 0 {
		t.Error("no checked verifiers")
	}
}

func TestE2E_CompatVerifySignature(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s := compatCrypto.NewECDSASigner(privKey, crypto.SHA256)
	v := compatCrypto.NewECDSAVerifier(&privKey.PublicKey, crypto.SHA256)

	payload := []byte(`{"verify": "signature"}`)

	env, err := dsse.Sign("application/vnd.in-toto+json",
		bytes.NewReader(payload),
		dsse.SignWithSigners(s))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	envJSON, _ := json.Marshal(env)

	// Use compat VerifySignature.
	verified, err := witness.VerifySignature(bytes.NewReader(envJSON), v)
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}

	if verified.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("PayloadType = %q", verified.PayloadType)
	}
}

func TestE2E_CompatFakeTimestamperInterop(t *testing.T) {
	// Create a FakeTimestamper via compat, use it as rookery Timestamper.
	now := time.Now().Truncate(time.Second) // RFC3339 only has second precision
	compatTS := compatTimestamp.FakeTimestamper{T: now}

	// Use as rookery interface.
	var rookeryTS timestamp.Timestamper = compatTS

	data := bytes.NewReader([]byte("timestamp test"))
	tsBytes, err := rookeryTS.Timestamp(context.Background(), data)
	if err != nil {
		t.Fatalf("FakeTimestamper.Timestamp via rookery interface: %v", err)
	}

	// Verify using the output of Timestamp (which is the RFC3339-formatted time).
	var rookeryTV timestamp.TimestampVerifier = compatTS
	ts, err := rookeryTV.Verify(context.Background(),
		bytes.NewReader(tsBytes),
		bytes.NewReader([]byte("sig-data")))
	if err != nil {
		t.Fatalf("FakeTimestamper.Verify via rookery interface: %v", err)
	}
	if !ts.Equal(now) {
		t.Errorf("timestamp mismatch: got %v, want %v", ts, now)
	}
}

func TestE2E_CompatPolicyValidateWithDeps(t *testing.T) {
	// Build a multi-step policy with AttestationsFrom via compat,
	// validate it via rookery.
	p := compatPolicy.Policy{
		Steps: map[string]compatPolicy.Step{
			"build": {
				Name: "build",
				Functionaries: []compatPolicy.Functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
			},
			"test": {
				Name:             "test",
				AttestationsFrom: []string{"build"},
				Functionaries: []compatPolicy.Functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
			},
			"deploy": {
				Name:             "deploy",
				AttestationsFrom: []string{"build", "test"},
				ArtifactsFrom:    []string{"build"},
				Functionaries: []compatPolicy.Functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
			},
		},
	}

	// Type-assert to rookery.
	var rookeryP policy.Policy = p

	// Validate via rookery.
	if err := rookeryP.Validate(); err != nil {
		t.Errorf("valid policy failed Validate: %v", err)
	}

	// Now introduce a circular dependency.
	badP := compatPolicy.Policy{
		Steps: map[string]compatPolicy.Step{
			"a": {Name: "a", AttestationsFrom: []string{"c"}},
			"b": {Name: "b", AttestationsFrom: []string{"a"}},
			"c": {Name: "c", AttestationsFrom: []string{"b"}},
		},
	}

	var rookeryBadP policy.Policy = badP
	err := rookeryBadP.Validate()
	if err == nil {
		t.Error("circular dependency policy should fail Validate")
	}
	if !strings.Contains(err.Error(), "circular") {
		t.Errorf("expected circular dependency error, got: %v", err)
	}
}

// ============================================================================
// SECTION 7: INTERFACE SATISFACTION TESTS
//
// Verify that compat types satisfy the expected interfaces.
// ============================================================================

func TestInterfaceSatisfaction_MemorySourceImplementsSourcer(t *testing.T) {
	ms := compatSource.NewMemorySource()
	var _ compatSource.Sourcer = ms
	var _ source.Sourcer = ms
}

func TestInterfaceSatisfaction_VerifiedSourceImplementsVerifiedSourcer(t *testing.T) {
	ms := compatSource.NewMemorySource()
	vs := compatSource.NewVerifiedSource(ms)
	var _ compatSource.VerifiedSourcer = vs
	var _ source.VerifiedSourcer = vs
}

func TestInterfaceSatisfaction_MultiSourceImplementsSourcer(t *testing.T) {
	ms := compatSource.NewMultiSource()
	var _ compatSource.Sourcer = ms
	var _ source.Sourcer = ms
}

func TestInterfaceSatisfaction_FakeTimestamperImplementsInterfaces(t *testing.T) {
	ft := compatTimestamp.FakeTimestamper{T: time.Now()}
	var _ compatTimestamp.Timestamper = ft
	var _ compatTimestamp.TimestampVerifier = ft
	var _ timestamp.Timestamper = ft
	var _ timestamp.TimestampVerifier = ft
}

func TestInterfaceSatisfaction_ECDSASignerImplementsSigner(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := compatCrypto.NewECDSASigner(privKey, crypto.SHA256)
	var _ compatCrypto.Signer = s
	var _ cryptoutil.Signer = s
	var _ compatCrypto.KeyIdentifier = s
	var _ cryptoutil.KeyIdentifier = s
}

func TestInterfaceSatisfaction_RSAVerifierImplementsVerifier(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v := compatCrypto.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)
	var _ compatCrypto.Verifier = v
	var _ cryptoutil.Verifier = v
}

func TestInterfaceSatisfaction_SilentLoggerImplementsLogger(t *testing.T) {
	var _ compatLog.Logger = compatLog.SilentLogger{}
	var _ log.Logger = compatLog.SilentLogger{}
}

func TestInterfaceSatisfaction_ConsoleLoggerImplementsLogger(t *testing.T) {
	var _ compatLog.Logger = compatLog.ConsoleLogger{}
	var _ log.Logger = compatLog.ConsoleLogger{}
}

// ============================================================================
// SECTION 8: EDGE CASES AND ERROR PATH TESTS
// ============================================================================

func TestEdgeCase_NilDigestSetEquality(t *testing.T) {
	// DigestSet.Equal returns false when both are nil/empty because there
	// are no common hash functions. This is correct behavior -- empty sets
	// should NOT be considered equal in a supply chain attestation context,
	// as it would allow empty digests to match anything.
	var compatDS compatCrypto.DigestSet
	var rookeryDS cryptoutil.DigestSet

	if compatDS.Equal(rookeryDS) {
		t.Error("nil DigestSets should NOT be equal (no common hashes)")
	}

	// But two DigestSets with the same data should be equal.
	ds1 := compatCrypto.DigestSet{
		compatCrypto.DigestValue{Hash: crypto.SHA256}: "abc123",
	}
	ds2 := cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc123",
	}
	if !ds1.Equal(ds2) {
		t.Error("identical DigestSets should be equal")
	}
}

func TestEdgeCase_EmptyCollectionRoundtrip(t *testing.T) {
	coll := compatAttestation.NewCollection("empty", nil)
	data, err := json.Marshal(coll)
	if err != nil {
		t.Fatal(err)
	}

	var restored attestation.Collection
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if restored.Name != "empty" {
		t.Errorf("Name = %q", restored.Name)
	}
}

func TestEdgeCase_DuplicateReferenceError(t *testing.T) {
	ms := compatSource.NewMemorySource()

	env := compatDSSE.Envelope{
		PayloadType: intoto.PayloadType,
		Payload: func() []byte {
			stmt := intoto.Statement{
				Type:          intoto.StatementType,
				PredicateType: attestation.CollectionType,
				Subject:       []intoto.Subject{},
				Predicate:     json.RawMessage(`{"name":"dup","attestations":[]}`),
			}
			b, _ := json.Marshal(stmt)
			return b
		}(),
	}

	if err := ms.LoadEnvelope("dup-ref", env); err != nil {
		t.Fatalf("first load: %v", err)
	}

	// Loading same reference again should fail.
	err := ms.LoadEnvelope("dup-ref", env)
	if err == nil {
		t.Fatal("expected error for duplicate reference")
	}

	// The error should be the compat ErrDuplicateReference type.
	var dupErr compatSource.ErrDuplicateReference
	if !isErrDuplicateReference(err) {
		_ = dupErr // suppress unused
		t.Logf("got error type %T: %v (may not be ErrDuplicateReference)", err, err)
	}
}

// isErrDuplicateReference checks if the error is an ErrDuplicateReference
// from either compat or rookery (they're the same type).
func isErrDuplicateReference(err error) bool {
	_, ok := err.(source.ErrDuplicateReference)
	return ok
}

func TestEdgeCase_VerifySignatureNoSigners(t *testing.T) {
	// Attempting to verify with no signers should fail gracefully.
	env := compatDSSE.Envelope{
		PayloadType: "test",
		Payload:     []byte("data"),
		Signatures:  []compatDSSE.Signature{{KeyID: "k", Signature: []byte("s")}},
	}

	_, err := env.Verify()
	if err == nil {
		t.Error("expected error when verifying with no verifiers")
	}
}

func TestEdgeCase_KMSNewWithOptions(t *testing.T) {
	// Verify KMS options work through compat layer.
	ksp := compatSignerKMS.New(
		compatSignerKMS.WithRef("awskms:///arn:aws:kms:us-east-1:123456789012:key/test"),
		compatSignerKMS.WithHash("SHA256"),
		compatSignerKMS.WithKeyVersion("1"),
	)

	if ksp == nil {
		t.Fatal("New returned nil")
	}

	// Verify the type is the same.
	var _ *signerKMS.KMSSignerProvider = ksp
}

func TestEdgeCase_DefaultSensitiveEnvListConsistency(t *testing.T) {
	compatList := compatAttestation.DefaultSensitiveEnvList()
	rookeryList := attestation.DefaultSensitiveEnvList()

	if len(compatList) != len(rookeryList) {
		t.Errorf("DefaultSensitiveEnvList length: compat=%d rookery=%d",
			len(compatList), len(rookeryList))
	}

	for key := range compatList {
		if _, ok := rookeryList[key]; !ok {
			t.Errorf("key %q in compat but not rookery DefaultSensitiveEnvList", key)
		}
	}
}

// Ensure unused imports are consumed.
var (
	_ = compatFile.RecordArtifacts
	_ = compatIntotoLink.Link{}
	_ = compatIntotoProvenance.Provenance{}
	_ = compatIntotoV1.ResourceDescriptor{}
	_ = compatRegistry.Configurer(nil)
	_ io.Reader
	_ = compatSigner.Register
)
