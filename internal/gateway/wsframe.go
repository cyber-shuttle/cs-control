package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"time"

	"github.com/gorilla/websocket"
)

// Requests have already passed the exact-origin OAuth boundary, so CheckOrigin
// adds nothing on top of it.
func newUpgrader(subprotocols ...string) websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		Subprotocols:    subprotocols,
		CheckOrigin:     func(*http.Request) bool { return true },
	}
}

type clientFrame struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

type serverFrame struct {
	Type    string `json:"type"`
	Code    *int   `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

func exitFrame(code int, message string) serverFrame {
	return serverFrame{Type: "exit", Code: &code, Message: message}
}

// Reports a fixed message rather than the process error, so no diagnostic from
// the remote host reaches the browser.
func exitDetails(err error) (int, string) {
	if err == nil {
		return 0, ""
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), "SSH authentication failed"
	}
	return 1, "SSH authentication failed"
}

func pumpPTY(ctx context.Context, master io.Reader, out chan<- []byte, size int) {
	buffer := make([]byte, size)
	for {
		n, err := master.Read(buffer)
		if n > 0 {
			select {
			case out <- append([]byte(nil), buffer[:n]...):
			case <-ctx.Done():
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func writeJSON(conn *websocket.Conn, timeout time.Duration, frame any) error {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	return conn.WriteJSON(frame)
}

func writeBinary(conn *websocket.Conn, timeout time.Duration, data []byte) error {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	return conn.WriteMessage(websocket.BinaryMessage, data)
}
