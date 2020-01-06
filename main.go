package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"

	"github.com/jeremywohl/flatten"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

const (
	// SecretEnvVarName denotes the environment variable used to read the
	// Github webhook shared secret from.
	SecretEnvVarName = "LOGHOOK_GITHUB_WEBHOOK_SECRET"
)

type regexpSliceFlag []*regexp.Regexp

func (i *regexpSliceFlag) String() string {
	return "a collection of regular expressions"
}

func (i *regexpSliceFlag) Set(value string) error {
	*i = append(*i, regexp.MustCompile(value))
	return nil
}

// Config contains the runtime configuration data for loghook.
type Config struct {
	Path           *string
	Secret         *string
	ReceiverListen *string
	HealthListen   *string
	Counters       *prometheus.CounterVec
	SkipVerify     *bool
	SkipFieldsRe   regexpSliceFlag
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
	if *config.Secret != "" && !*config.SkipVerify {
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
	structuredevent := make(map[string]interface{})
	err := json.Unmarshal(body, &structuredevent)
	if err != nil {
		log.Error().Err(err).Bool("github_json_ok", false).Msg("unmarshaling Github event")
		return
	}
	flatevent, err := flatten.Flatten(structuredevent, "github_event_", flatten.SeparatorStyle{Middle: "_"})
	if err != nil {
		log.Error().Err(err).Bool("github_json_ok", false).Msg("flattening Github event")
		return
	}
	event := req.Header.Get("X-GitHub-Event")
	logevent := log.Info()
	for k, v := range flatevent {
		emit := true
		for _, skipre := range config.SkipFieldsRe {
			if skipre.MatchString(k) {
				emit = false
				break
			}
		}
		if emit {
			logevent = logevent.Interface(k, v)
		}
	}
	logevent.Str("github_event", event)
	labels := prometheus.Labels{"event": event, "repository": ""}
	if reponame, found := flatevent["github_event_repository_full_name"]; found {
		labels["repository"] = reponame.(string)
	}
	config.Counters.With(labels).Inc()
	logevent.Msg("received an event")
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
		[]string{"event", "repository"},
	)
	prometheus.MustRegister(events)
	return events
}

func healthAndMetricsEndpoint(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "OK") })
	mux.Handle("/metrics", promhttp.Handler())
	server := &http.Server{Addr: addr, Handler: mux}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal().Err(err).Msg("can't start metrics/health web listener")
	}
}

func postEndpoint(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc(*config.Path, handler)
	server := &http.Server{Addr: addr, Handler: mux}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal().Err(err).Msg("can't start log-receiver web listener")
	}
}

func main() {
	secret := os.Getenv(SecretEnvVarName)
	config = Config{
		Path:           flag.String("receiver", "/post", "specify the path that Github will post to"),
		ReceiverListen: flag.String("receiver-listen", ":3000", "[address]:port to bind to for receiving webhook payloads"),
		HealthListen:   flag.String("health-listen", ":3001", "[address]:port to bind to for exposing healthcheck and metrics"),
		SkipVerify:     flag.Bool("skip-verify", false, "don't verify message digests. For simplifying testing, only! Don't use in production!"),
		Secret:         &secret,
		Counters:       initMetrics(),
	}
	flag.Var(&config.SkipFieldsRe, "skip-fields-regex", "RE2 regular expression to filter out fields by flattened field name. Can be specified more than once")
	flag.Parse()
	go healthAndMetricsEndpoint(*config.HealthListen)
	postEndpoint(*config.ReceiverListen)
}
