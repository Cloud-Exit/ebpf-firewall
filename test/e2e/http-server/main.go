package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	var clientURL string
	var expectBody string
	var expectFailure bool
	flag.StringVar(&clientURL, "client-url", os.Getenv("CLIENT_URL"), "URL to request in client mode")
	flag.StringVar(&expectBody, "expect-body", os.Getenv("EXPECT_BODY"), "response body substring required in client mode")
	flag.BoolVar(&expectFailure, "expect-failure", os.Getenv("EXPECT_FAILURE") == "true", "expect the client request to fail")
	flag.Parse()

	if clientURL != "" {
		runClient(clientURL, expectBody, expectFailure)
		return
	}

	listenAddr := getenv("LISTEN_ADDR", ":8080")
	serveFile := os.Getenv("SERVE_FILE")
	response := getenv("RESPONSE", "ok")

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if serveFile != "" {
			data, err := os.ReadFile(serveFile)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(data)
			return
		}
		_, _ = w.Write([]byte(response))
	})

	log.Printf("listening on %s", listenAddr)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatal(err)
	}
}

func runClient(url, expectBody string, expectFailure bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		finish(expectFailure, err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		finish(expectFailure, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		finish(expectFailure, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		finish(expectFailure, fmt.Errorf("status=%s body=%s", resp.Status, string(body)))
	}
	if expectBody != "" && !strings.Contains(string(body), expectBody) {
		finish(expectFailure, fmt.Errorf("body %q does not contain %q", string(body), expectBody))
	}
	if expectFailure {
		log.Fatalf("request unexpectedly succeeded: status=%s body=%s", resp.Status, string(body))
	}
	log.Printf("request succeeded: status=%s", resp.Status)
}

func finish(expectFailure bool, err error) {
	if expectFailure {
		log.Printf("request failed as expected: %v", err)
		os.Exit(0)
	}
	log.Fatal(err)
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
