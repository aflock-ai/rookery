// jade:ring local

package fileinventory

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInventoryRejectsInvalidUnicodeScalars(t *testing.T) {
	_, body, err := Encode("product", "walk", []Entry{{Path: "a", FileDigest: strings.Repeat("0", 64)}})
	require.NoError(t, err)
	for _, path := range []string{`"\ud800"`, `"\udfff"`, `"\ud800x"`, `"\ud800\ud800"`} {
		_, err := Decode(bytes.Replace(body, []byte(`"a"`), []byte(path), 1), "product")
		require.Error(t, err, "unpaired surrogates must not silently become replacement characters")
	}
	for _, path := range []string{`"\ud83d\ude00"`, `"\ufffd"`, `"\\ud800"`} {
		_, err := Decode(bytes.Replace(body, []byte(`"a"`), []byte(path), 1), "product")
		require.NoError(t, err)
	}
}

func TestInventoryPayloadByteLimit(t *testing.T) {
	_, err := Decode(make([]byte, MaxBytes+1), "product")
	require.ErrorContains(t, err, "exceeds")
}
