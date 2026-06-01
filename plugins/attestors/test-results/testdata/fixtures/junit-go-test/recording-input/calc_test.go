package junitgen

import "testing"

// TestAdd passes.
func TestAdd(t *testing.T) {
	if Add(2, 3) != 5 {
		t.Errorf("Add(2,3) = %d, want 5", Add(2, 3))
	}
}

// TestSub passes.
func TestSub(t *testing.T) {
	if Sub(5, 3) != 2 {
		t.Errorf("Sub(5,3) = %d, want 2", Sub(5, 3))
	}
}

// TestMul passes.
func TestMul(t *testing.T) {
	if Mul(4, 5) != 20 {
		t.Errorf("Mul(4,5) = %d, want 20", Mul(4, 5))
	}
}

// TestSkipMe is skipped so the predicate exercises the skipped bucket.
func TestSkipMe(t *testing.T) {
	t.Skip("not ready")
}

// TestSubFails fails deterministically to populate a test-failure: subject.
func TestSubFails(t *testing.T) {
	t.Errorf("intentional failure in suite")
}

// TestMulFails fails deterministically to populate a second test-failure: subject.
func TestMulFails(t *testing.T) {
	t.Errorf("second intentional failure")
}
