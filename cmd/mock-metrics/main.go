package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

type PromResponse struct {
	Status string   `json:"status"`
	Data   PromData `json:"data"`
}

type PromData struct {
	ResultType string       `json:"resultType"`
	Result     []PromResult `json:"result"`
}

type PromResult struct {
	Metric map[string]string `json:"metric"`
	Value  [2]interface{}    `json:"value"`
}

var (
	startTime  time.Time
	switchTime time.Time
	once       sync.Once
)

func main() {
	once.Do(func() {
		startTime = time.Now()
		switchTime = startTime.Add(20 * time.Second)
		log.Printf("mock metrics started at %s", startTime.Format(time.RFC3339Nano))
		log.Printf("metric will switch to abnormal at %s", switchTime.Format(time.RFC3339Nano))
	})

	http.HandleFunc("/api/v1/query", func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		query := r.URL.Query().Get("query")

		value := "1"
		statusText := "normal"
		if !now.Before(switchTime) {
			value = "0"
			statusText = "abnormal"
		}

		resp := PromResponse{
			Status: "success",
			Data: PromData{
				ResultType: "vector",
				Result: []PromResult{
					{
						Metric: map[string]string{
							"__name__": "mock_metric",
							"job":      "mock-metrics",
						},
						Value: [2]interface{}{
							float64(now.Unix()),
							value,
						},
					},
				},
			},
		}

		log.Printf("query=%q value=%s status=%s now=%s switchTime=%s",
			query, value, statusText,
			now.Format(time.RFC3339Nano),
			switchTime.Format(time.RFC3339Nano),
		)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
