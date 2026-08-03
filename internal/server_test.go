package internal

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sapiderman/tenkei-register/config"
)

func TestServeWith(t *testing.T) {
	cases := []struct {
		name        string
		readTimeout string
	}{
		{"valid timeout", "5s"},
		{"invalid timeout falls back to default", "garbage"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("ok"))
			})
			cfg := config.Config{
				Server: config.ServerConfig{Port: "0", ReadHeaderTimeout: tc.readTimeout, Version: "test"},
			}

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- ServeWith(ctx, l, handler, cfg) }()

			// Wait until the server accepts requests.
			client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
			var resp *http.Response
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				resp, err = client.Get("http://" + l.Addr().String())
				if err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err != nil {
				cancel()
				<-done
				t.Fatalf("server never became ready: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("status = %d, want 200", resp.StatusCode)
			}

			// Cancel the context: ServeWith must shut down gracefully and return nil.
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("ServeWith returned error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("ServeWith did not return after context cancellation")
			}
		})
	}
}
