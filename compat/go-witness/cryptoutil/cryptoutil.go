// Package cryptoutil is a compatibility shim mapping go-witness cryptoutil to rookery.
package cryptoutil

import (
	rookery "github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// Types
type PEMType = rookery.PEMType
type DigestValue = rookery.DigestValue
type DigestSet = rookery.DigestSet
type ErrUnsupportedPEM = rookery.ErrUnsupportedPEM
type ErrInvalidPemBlock = rookery.ErrInvalidPemBlock
type ErrUnsupportedHash = rookery.ErrUnsupportedHash
type ErrUnsupportedKeyType = rookery.ErrUnsupportedKeyType
type ErrVerifyFailed = rookery.ErrVerifyFailed
type ErrInvalidSigner = rookery.ErrInvalidSigner
type ErrInvalidCertificate = rookery.ErrInvalidCertificate
type RSASigner = rookery.RSASigner
type RSAVerifier = rookery.RSAVerifier
type ECDSASigner = rookery.ECDSASigner
type ECDSAVerifier = rookery.ECDSAVerifier
type ED25519Signer = rookery.ED25519Signer
type ED25519Verifier = rookery.ED25519Verifier
type X509Verifier = rookery.X509Verifier
type X509Signer = rookery.X509Signer
type SignerOption = rookery.SignerOption
type VerifierOption = rookery.VerifierOption

// Interfaces
type Signer = rookery.Signer
type Verifier = rookery.Verifier
type KeyIdentifier = rookery.KeyIdentifier
type TrustBundler = rookery.TrustBundler

// Constants
const (
	PublicKeyPEMType      = rookery.PublicKeyPEMType
	PKCS1PublicKeyPEMType = rookery.PKCS1PublicKeyPEMType
)

// Functions
var DigestBytes = rookery.DigestBytes
var Digest = rookery.Digest
var HexEncode = rookery.HexEncode
var GeneratePublicKeyID = rookery.GeneratePublicKeyID
var PublicPemBytes = rookery.PublicPemBytes
var UnmarshalPEMToPublicKey = rookery.UnmarshalPEMToPublicKey
var TryParsePEMBlock = rookery.TryParsePEMBlock
var TryParsePEMBlockWithPassword = rookery.TryParsePEMBlockWithPassword
var TryParseKeyFromReader = rookery.TryParseKeyFromReader
var TryParseKeyFromReaderWithPassword = rookery.TryParseKeyFromReaderWithPassword
var TryParseCertificate = rookery.TryParseCertificate
var ComputeDigest = rookery.ComputeDigest
var HashToString = rookery.HashToString
var HashFromString = rookery.HashFromString
var NewDigestSet = rookery.NewDigestSet
var CalculateDigestSet = rookery.CalculateDigestSet
var CalculateDigestSetFromBytes = rookery.CalculateDigestSetFromBytes
var CalculateDigestSetFromFile = rookery.CalculateDigestSetFromFile
var CalculateDigestSetFromDir = rookery.CalculateDigestSetFromDir
var NewSigner = rookery.NewSigner
var NewSignerFromReader = rookery.NewSignerFromReader
var SignWithCertificate = rookery.SignWithCertificate
var SignWithIntermediates = rookery.SignWithIntermediates
var SignWithRoots = rookery.SignWithRoots
var SignWithHash = rookery.SignWithHash
var NewVerifier = rookery.NewVerifier
var NewVerifierFromReader = rookery.NewVerifierFromReader
var VerifyWithRoots = rookery.VerifyWithRoots
var VerifyWithIntermediates = rookery.VerifyWithIntermediates
var VerifyWithHash = rookery.VerifyWithHash
var VerifyWithTrustedTime = rookery.VerifyWithTrustedTime
var NewRSASigner = rookery.NewRSASigner
var NewRSAVerifier = rookery.NewRSAVerifier
var NewECDSASigner = rookery.NewECDSASigner
var NewECDSAVerifier = rookery.NewECDSAVerifier
var NewED25519Signer = rookery.NewED25519Signer
var NewED25519Verifier = rookery.NewED25519Verifier
var NewX509Verifier = rookery.NewX509Verifier
var NewX509Signer = rookery.NewX509Signer
var DirhHashSha256 = rookery.DirhHashSha256
