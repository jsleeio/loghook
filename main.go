package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

const (
	// SecretEnvVarName denotes the environment variable used to read the
	// Github webhook shared secret from.
	SecretEnvVarName = "LOGHOOK_GITHUB_WEBHOOK_SECRET"
)

// Config contains the runtime configuration data for loghook.
type Config struct {
	Path     *string
	Secret   *string
	Listen   *string
	Counters *prometheus.CounterVec
}

var config Config

// sanityCheckRequest does not satisfy the http.Handler interface; it returns
// a "should you continue?" value instead. If False, handling of the request
// should be aborted. If True, the request body is also returned.
// Mostly from https://github.com/phayes/hookserve/blob/master/hookserve/hookserve.go
// THANKS!
func sanityCheckRequest(w http.ResponseWriter, req *http.Request) (bool, []byte) {
	if req.Method != "POST" {
		http.Error(w, "405 Method not allowed", http.StatusMethodNotAllowed)
		return false, nil
	}
	if req.URL.Path != *config.Path {
		http.Error(w, "404 Not found", http.StatusNotFound)
		return false, nil
	}

	eventType := req.Header.Get("X-GitHub-Event")
	if eventType == "" {
		http.Error(w, "400 Bad Request - Missing X-GitHub-Event Header", http.StatusBadRequest)
		return false, nil
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false, nil
	}

	// If we have a Secret set, we should check the MAC
	if *config.Secret != "" {
		sig := req.Header.Get("X-Hub-Signature")

		if sig == "" {
			http.Error(w, "403 Forbidden - Missing X-Hub-Signature required for HMAC verification", http.StatusForbidden)
			return false, nil
		}

		mac := hmac.New(sha1.New, []byte(*config.Secret))
		mac.Write(body)
		expectedMAC := mac.Sum(nil)
		expectedSig := "sha1=" + hex.EncodeToString(expectedMAC)
		if !hmac.Equal([]byte(expectedSig), []byte(sig)) {
			http.Error(w, "403 Forbidden - HMAC verification failed", http.StatusForbidden)
			return false, nil
		}
	}
	return true, body
}

func handler(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	ok, body := sanityCheckRequest(w, req)
	if !ok {
		return
	}
	// for the sake of simplicity, don't actually unmarshal the JSON payload, just compact it
	buf := new(bytes.Buffer)
	err := json.Compact(buf, body)
	jsonOk := true
	logBody := string(body)
	if err != nil {
		// on error, log the untrammeled JSON for debug purposes. This should not be an easy
		// vector for log spam/denial of service, as we don't get this far without validating
		// the message against the HMAC shared secret.
		log.Warn().Str("github_event_raw", string(body)).Msg("Error compacting JSON payload")
		jsonOk = false
	} else {
		logBody = buf.String()
	}
	event := req.Header.Get("X-GitHub-Event")
	config.Counters.With(prometheus.Labels{"event": event}).Inc()
	log.Info().Str("github_event_type", event).Bool("github_json_ok", jsonOk).Str("github_event", logBody).Msg("Event received.")
}

func health(w http.ResponseWriter, req *http.Request) {
	io.WriteString(w, "OK")
}

func initMetrics() *prometheus.CounterVec {
	events := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "github_events_total",
			Help: "How many GitHub events were received and logged, partitioned by event type",
		},
		[]string{"event"},
	)
	prometheus.MustRegister(events)
	return events
}

func main() {
	secret := os.Getenv(SecretEnvVarName)
	config = Config{
		Path:     flag.String("receiver", "/post", "specify the path that Github will post to"),
		Listen:   flag.String("listen", ":3000", "[address]:port to bind to"),
		Secret:   &secret,
		Counters: initMetrics(),
	}
	flag.Parse()
	http.HandleFunc(*config.Path, handler)
	http.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) { io.WriteString(w, "OK") })
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(*config.Listen, nil)
}
