package httpx

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWriteJSON(t *testing.T) {
	recorder := httptest.NewRecorder()
	WriteJSON(recorder, http.StatusCreated, map[string]int{"answer": 42})

	if recorder.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusCreated)
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
	if got, want := recorder.Body.String(), "{\"answer\":42}\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestError(t *testing.T) {
	recorder := httptest.NewRecorder()
	Error(recorder, http.StatusForbidden, "denied")

	if recorder.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if got, want := recorder.Body.String(), "{\"error\":\"denied\"}\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestReadJSON(t *testing.T) {
	type subjectBody struct {
		Subject string `json:"subject"`
	}
	tests := []struct {
		name      string
		body      string
		wantError bool
	}{
		{"valid", `{"subject":"pmu-7"}`, false},
		{"unknown field", `{"subject":"pmu-7","admin":true}`, true},
		{"trailing data", `{"subject":"pmu-7"}{"subject":"evil"}`, true},
		{"malformed", `{"subject":`, true},
		{"empty", ``, true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(testCase.body))
			var got subjectBody
			err := ReadJSON(httptest.NewRecorder(), request, &got)
			gotError := err != nil
			if gotError != testCase.wantError {
				t.Fatalf("ReadJSON error = %v, wantError %v", err, testCase.wantError)
			}
			if !testCase.wantError && got.Subject != "pmu-7" {
				t.Errorf("Subject = %q, want pmu-7", got.Subject)
			}
		})
	}
}

func TestReadJSONRejectsOversizedBody(t *testing.T) {
	body := `{"subject":"` + strings.Repeat("a", MaxBody) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	var decoded struct {
		Subject string `json:"subject"`
	}
	err := ReadJSON(httptest.NewRecorder(), request, &decoded)

	var tooLarge *http.MaxBytesError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("ReadJSON error = %v, want *http.MaxBytesError", err)
	}
}

func TestRunShutsDownWhenContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	server := NewServer("127.0.0.1:0", http.NotFoundHandler())

	runResult := make(chan error, 1)
	go func() { runResult <- Run(ctx, server) }()
	cancel()

	select {
	case err := <-runResult:
		if err != nil {
			t.Fatalf("Run returned %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func TestRunFailsWhenPortIsInUse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	server := NewServer(listener.Addr().String(), http.NotFoundHandler())
	if err := Run(context.Background(), server); err == nil {
		t.Fatal("Run returned nil on a port that is in use, want an error")
	}
}
