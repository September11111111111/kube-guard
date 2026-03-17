package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryPrometheusInstant(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		baseURL  string
		promql   string
		handler  http.HandlerFunc
		want     float64
		wantErr  bool
		checkReq bool
	}{
		{
			name:    "empty baseURL",
			baseURL: "",
			promql:  "up",
			want:    0,
			wantErr: true,
		},
		{
			name:    "invalid baseURL",
			baseURL: "://bad-url",
			promql:  "up",
			want:    0,
			wantErr: true,
		},
		{
			name:   "success with one result",
			promql: "up",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{
					"status":"success",
					"data":{
						"resultType":"vector",
						"result":[
							{
								"metric":{},
								"value":[1710000000,"12.34"]
							}
						]
					}
				}`))
			},
			want:     12.34,
			wantErr:  false,
			checkReq: true,
		},
		{
			name:   "success with empty result returns zero",
			promql: "up",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{
					"status":"success",
					"data":{
						"resultType":"vector",
						"result":[]
					}
				}`))
			},
			want:     0,
			wantErr:  false,
			checkReq: true,
		},
		{
			name:   "success with short value returns zero",
			promql: "up",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{
					"status":"success",
					"data":{
						"resultType":"vector",
						"result":[
							{
								"metric":{},
								"value":[1710000000]
							}
						]
					}
				}`))
			},
			want:     0,
			wantErr:  false,
			checkReq: true,
		},
		{
			name:   "non success status returns error",
			promql: "up",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{
					"status":"error",
					"data":{
						"resultType":"vector",
						"result":[]
					}
				}`))
			},
			want:     0,
			wantErr:  true,
			checkReq: true,
		},
		{
			name:   "invalid json returns error",
			promql: "up",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{invalid json`))
			},
			want:     0,
			wantErr:  true,
			checkReq: true,
		},
		{
			name:   "unexpected value type returns error",
			promql: "up",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{
					"status":"success",
					"data":{
						"resultType":"vector",
						"result":[
							{
								"metric":{},
								"value":[1710000000,12.34]
							}
						]
					}
				}`))
			},
			want:     0,
			wantErr:  true,
			checkReq: true,
		},
		{
			name:   "invalid numeric string returns error",
			promql: "up",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{
					"status":"success",
					"data":{
						"resultType":"vector",
						"result":[
							{
								"metric":{},
								"value":[1710000000,"not-a-number"]
							}
						]
					}
				}`))
			},
			want:     0,
			wantErr:  true,
			checkReq: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			baseURL := tt.baseURL
			if tt.handler != nil {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if tt.checkReq {
						if r.Method != http.MethodGet {
							t.Fatalf("method = %s, want GET", r.Method)
						}
						if r.URL.Path != "/api/v1/query" {
							t.Fatalf("path = %s, want /api/v1/query", r.URL.Path)
						}
						if got := r.URL.Query().Get("query"); got != tt.promql {
							t.Fatalf("query param = %q, want %q", got, tt.promql)
						}
					}
					tt.handler(w, r)
				}))
				defer server.Close()
				baseURL = server.URL
			}

			got, err := queryPrometheusInstant(context.Background(), baseURL, tt.promql)
			if (err != nil) != tt.wantErr {
				t.Fatalf("queryPrometheusInstant(%q, %q) error = %v, wantErr %v", baseURL, tt.promql, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("queryPrometheusInstant(%q, %q) = %v, want %v", baseURL, tt.promql, got, tt.want)
			}
		})
	}
}

func TestQueryPrometheusInstant_BaseURLWithPath(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotQuery string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"status":"success",
			"data":{
				"resultType":"vector",
				"result":[
					{
						"metric":{},
						"value":[1710000000,"1.5"]
					}
				]
			}
		}`))
	}))
	defer server.Close()

	baseURL := server.URL + "/prometheus/"
	got, err := queryPrometheusInstant(context.Background(), baseURL, `sum(rate(http_requests_total[5m]))`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 1.5 {
		t.Fatalf("got %v, want 1.5", got)
	}
	if gotPath != "/prometheus/api/v1/query" {
		t.Fatalf("path = %q, want %q", gotPath, "/prometheus/api/v1/query")
	}
	if gotQuery != `sum(rate(http_requests_total[5m]))` {
		t.Fatalf("query = %q, want %q", gotQuery, `sum(rate(http_requests_total[5m]))`)
	}
}
