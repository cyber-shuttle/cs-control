// Package testutil holds the two assertions nearly every test in the module makes: no error, and one value
// equals another. It sits below every other package so any test file can import it.
//
//	Check, Equal
package testutil

import "testing"

func Check(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func Equal[T comparable](t testing.TB, got, want T, what string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
}
