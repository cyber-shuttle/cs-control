// Package testutil holds the small assertions and waits shared across otherwise independent tests. It sits below
// every production package so tests reuse mechanics without importing another domain.
package testutil

import (
	"net/http"
	"net/http/httptest"
	"os"
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

func RemainsBlocked[T any](t testing.TB, done <-chan T, what string) {
	t.Helper()
	select {
	case result := <-done:
		t.Fatalf("%s: %v", what, result)
	case <-time.After(100 * time.Millisecond):
	}
}

func Serve(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func WriteScript(t testing.TB, path, body string) {
	t.Helper()
	Check(t, os.WriteFile(path, []byte(body), 0o700))
}

func Eventually(t testing.TB, timeout time.Duration, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func WaitForFile(t testing.TB, path string) {
	t.Helper()
	Eventually(t, 3*time.Second, path, func() bool {
		info, err := os.Stat(path)
		return err == nil && info.Size() > 0
	})
}
