package gateway

import (
	"context"
	"io"
	"time"

	"github.com/gorilla/websocket"
)

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
