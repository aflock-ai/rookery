// Package registry is a compatibility shim mapping go-witness registry to rookery.
package registry

import (
	rookery "github.com/aflock-ai/rookery/attestation/registry"
)

// Types — generic type aliases require Go 1.24+
type Registry[T any] = rookery.Registry[T]
type FactoryFunc[T any] = rookery.FactoryFunc[T]
type Entry[T any] = rookery.Entry[T]
type ConfigOption[T any, TOption Option] = rookery.ConfigOption[T, TOption]
type Option = rookery.Option

// Interfaces
type Configurer = rookery.Configurer

// Note: Generic functions (New, SetOptions, IntConfigOption, etc.) cannot be
// aliased as package-level vars in Go. They are available through the type
// aliases above — callers use rookery.New[T]() via the Registry[T] alias.
// In practice, attestor plugins never call these directly; they use
// attestation.RegisterAttestation() which handles registry internals.
