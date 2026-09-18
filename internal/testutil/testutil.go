// Package testutil holds what nearly every test in the module does: check no error, compare two values, wait
// on an error channel, and serve one request through a handler. It sits below every other package so any test file can import it.
//
//	Check, Equal, Within, Serve
package testutil

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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

func Within(t testing.TB, done <-chan error, timeout time.Duration, what string) {
	t.Helper()
	select {
	case err := <-done:
		Check(t, err)
	case <-time.After(timeout):
		t.Fatal(what)
	}
}

func Serve(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
