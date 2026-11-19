package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"lensgate/internal/model"
	"lensgate/internal/store"
)

func TestHandleFlowDetail(t *testing.T) {
	st, err := store.New("", 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.AddFlowDetail(model.FlowDetail{
		Flow:    model.Flow{ID: "flow-1", Host: "api.openai.com", Path: "/v1/chat/completions"},
		Request: model.RequestDetail{Method: http.MethodPost, Body: `{"a":1}`},
	})
	srv := &Server{Store: st}

	cases := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"existing", http.MethodGet, "/api/flows/flow-1", http.StatusOK},
		{"missing", http.MethodGet, "/api/flows/nope", http.StatusNotFound},
		{"empty id", http.MethodGet, "/api/flows/", http.StatusNotFound},
		{"nested path", http.MethodGet, "/api/flows/flow-1/extra", http.StatusNotFound},
		{"wrong method", http.MethodPost, "/api/flows/flow-1", http.StatusMethodNotAllowed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.handleFlowDetail(rec, httptest.NewRequest(c.method, c.path, nil))
			if rec.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, c.wantStatus)
			}
			if c.wantStatus != http.StatusOK {
				return
			}
			var got model.FlowDetail
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got.Flow.ID != "flow-1" || got.Request.Body != `{"a":1}` {
				t.Fatalf("unexpected detail: %+v", got)
			}
		})
	}
}
