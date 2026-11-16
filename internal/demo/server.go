package demo

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/eudi-dev/ebw-dev/internal/trust"
)

//go:embed web
var webFiles embed.FS

type Config struct {
	// PublicURL is the base URL that browsers and the wallet use. It may
	// carry a path prefix.
	PublicURL       string
	WalletURL       string
	WalletPublicURL string
	ImprintURL      string
	BrandDir        string
	Version         string
}

type Server struct {
	config   Config
	public   *url.URL
	basePath string
	trust    *trust.Store
	pages    *template.Template
	handler  http.Handler
	client   *http.Client
	wallet   walletClient
	now      func() time.Time

	registrationMu sync.Mutex
	registrations  map[string]*registration

	mu       sync.Mutex
	mandates map[string]*Mandate
	runs     map[string]*Run
	requests map[string]*verifierRequest

	scenarioRequests map[string]*ScenarioRequest
}

// NewServer builds the server. Trust anchors load with LoadTrust or on the
// first use.
func NewServer(config Config) (*Server, error) {
	public, err := url.Parse(strings.TrimRight(config.PublicURL, "/"))
	if err != nil || public.Host == "" {
		return nil, errors.New("the public URL needs a scheme and a host")
	}
	if config.WalletPublicURL == "" {
		config.WalletPublicURL = config.WalletURL
	}
	config.PublicURL = public.String()
	config.WalletURL = strings.TrimRight(config.WalletURL, "/")
	config.WalletPublicURL = strings.TrimRight(config.WalletPublicURL, "/")
	pages, err := template.New("").Funcs(template.FuncMap{"lower": strings.ToLower}).ParseFS(webFiles, "web/*.html")
	if err != nil {
		return nil, err
	}
	server := &Server{
		config:        config,
		public:        public,
		basePath:      public.Path + "/",
		trust:         trust.NewStore(config.WalletURL),
		pages:         pages,
		wallet:        newWalletClient(config.WalletURL),
		now:           time.Now,
		mandates:      map[string]*Mandate{},
		runs:          map[string]*Run{},
		requests:      map[string]*verifierRequest{},
		registrations: map[string]*registration{},

		scenarioRequests: map[string]*ScenarioRequest{},
	}
	server.handler = server.routes()
	server.client = &http.Client{Timeout: 15 * time.Second, Transport: loopback{prefix: config.PublicURL, handler: server}}
	return server, nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFiles, "web/static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /brand/logo.svg", s.logo)
	mux.HandleFunc("GET /{$}", s.page("index.html"))
	mux.HandleFunc("GET /cases/{case}", s.page("case.html"))
	mux.HandleFunc("GET /scenarios/{scenario}", s.page("scenario.html"))
	mux.HandleFunc("GET /issuer", s.page("issuer.html"))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("GET /api/config", s.apiConfig)
	mux.HandleFunc("GET /api/trust", s.apiTrust)
	mux.HandleFunc("POST /api/mandates", s.createMandate)
	mux.HandleFunc("GET /api/mandates/{id}", s.getMandate)
	mux.HandleFunc("POST /api/mandates/{id}/runs", s.createRun)
	mux.HandleFunc("GET /api/runs/{id}", s.getRun)
	mux.HandleFunc("POST /agent/response", s.agentResponse)
	mux.HandleFunc("POST /api/scenarios/{scenario}/requests", s.createScenarioRequest)
	mux.HandleFunc("GET /api/scenarios/{scenario}/requests/{id}", s.getScenarioRequest)
	mux.HandleFunc("POST /scenarios/{scenario}/response", s.scenarioResponse)
	mux.HandleFunc("POST /api/offers", s.createIssuerOffer)
	mux.HandleFunc("GET /api/wallet/credentials", s.apiWalletCredentials)

	mux.HandleFunc("POST /verifier/{verifier}/requests", s.verifierCreate)
	mux.HandleFunc("POST /verifier/{verifier}/response", s.verifierResponse)
	mux.HandleFunc("GET /verifier/{verifier}/requests/{id}", s.verifierResult)
	return mux
}

// ServeHTTP serves requests with and without the path prefix of the public
// URL. A reverse proxy may strip the prefix or keep it.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	if prefix := s.public.Path; prefix != "" {
		if r.URL.Path == prefix {
			http.Redirect(w, r, prefix+"/", http.StatusPermanentRedirect) //nolint:gosec // the prefix comes from the configuration
			return
		}
		if strings.HasPrefix(r.URL.Path, prefix+"/") {
			http.StripPrefix(prefix, s.handler).ServeHTTP(w, r)
			return
		}
	}
	s.handler.ServeHTTP(w, r)
}

func (s *Server) url(path string) string {
	return s.config.PublicURL + path
}

type pageData struct {
	// BasePath is the path of the public URL with a trailing slash. Every
	// link of a page is relative to it.
	BasePath        string
	Page            string
	Cases           []Case
	Case            Case
	Verifier        Verifier
	Stranger        Verifier
	Scenarios       []Scenario
	Scenario        Scenario
	Offers          []OfferType
	Next            nextStep
	HasLogo         bool
	WalletPublicURL string
	ImprintURL      string
	Version         string
}

// nextStep is the box at the end of a page. It leads the visitor through the
// map in a fixed order: case 1, case 2, the notary, the bank.
type nextStep struct {
	Title string
	Text  string
	Label string
	Href  string
}

var nextSteps = map[string]nextStep{
	"case/supplier": {Title: "Next on the map: case 2.", Text: "The same agent approves an invoice inside Acme.", Label: "Go to case 2", Href: "cases/internal"},
	"case/internal": {Title: "Next on the map: the notary.", Text: "The wallet shows a power of attorney without an agent.", Label: "Open the notary", Href: "scenarios/poa"},
	"scenario/poa":  {Title: "Next on the map: the bank.", Text: "It asks for 2 credentials in one request.", Label: "Open the bank", Href: "scenarios/kyb"},
	"scenario/kyb":  {Title: "You have seen every part of the map.", Text: "Run any part again from the map."},
	"issuer/":       {Title: "Done here?", Text: "The map leads to the cases and scenarios."},
}

func (s *Server) page(name string) http.HandlerFunc {
	kind := strings.TrimSuffix(name, ".html")
	return func(w http.ResponseWriter, r *http.Request) {
		data := pageData{
			BasePath: s.basePath, Page: kind, Cases: cases, Stranger: verifiers[strangerID],
			Scenarios: scenarios, Offers: offerTypes,
			HasLogo: s.logoPath() != "", WalletPublicURL: s.config.WalletPublicURL, ImprintURL: s.config.ImprintURL, Version: s.config.Version,
		}
		if id := r.PathValue("case"); id != "" {
			index := slices.IndexFunc(data.Cases, func(c Case) bool { return c.ID == id })
			if index < 0 {
				http.NotFound(w, r)
				return
			}
			data.Case = data.Cases[index]
			data.Verifier = verifiers[data.Case.Verifier]
		}
		if id := r.PathValue("scenario"); id != "" {
			index := slices.IndexFunc(data.Scenarios, func(p Scenario) bool { return p.ID == id })
			if index < 0 {
				http.NotFound(w, r)
				return
			}
			data.Scenario = data.Scenarios[index]
		}
		data.Next = nextSteps[kind+"/"+r.PathValue("case")+r.PathValue("scenario")]
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if err := s.pages.ExecuteTemplate(w, name, data); err != nil {
			log.Printf("rendering %s: %v", name, err)
		}
	}
}

func (s *Server) logoPath() string {
	if s.config.BrandDir == "" {
		return ""
	}
	path := filepath.Join(s.config.BrandDir, "logo.svg")
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		return ""
	}
	return path
}

func (s *Server) logo(w http.ResponseWriter, r *http.Request) {
	path := s.logoPath()
	if path == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	// An SVG can carry scripts. This policy keeps a logo file from running any.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	http.ServeFile(w, r, path)
}

func (s *Server) apiConfig(w http.ResponseWriter, r *http.Request) {
	clientIDs := map[string]string{}
	for id := range verifiers {
		clientIDs[id] = s.verifierClientID(id)
	}
	// The page loads without the wallet. It then shows no client identifier.
	agentClientID := ""
	if registration, _, err := s.registered(r.Context(), agentService, ""); err != nil {
		log.Printf("registering the agent service: %v", err)
	} else {
		agentClientID = registration.clientID
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"public_url":          s.config.PublicURL,
		"wallet_url":          s.config.WalletPublicURL,
		"agent_client_id":     agentClientID,
		"verifier_client_ids": clientIDs,
		"cases":               cases,
		"verifiers":           verifiers,
		"check_labels":        checkLabels,
	})
}

// apiTrust names the public URL of the wallet as the source. The server loads
// the lists over the wallet URL, which browsers may not reach.
func (s *Server) apiTrust(w http.ResponseWriter, r *http.Request) {
	if err := s.ensureTrust(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, "trust_unavailable", err.Error())
		return
	}
	summary, err := s.trust.Summary()
	if err != nil {
		writeError(w, http.StatusBadGateway, "trust_unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, struct {
		trust.Summary
		Source string `json:"source"`
	}{summary, s.config.WalletPublicURL})
}

func (s *Server) LoadTrust(ctx context.Context) error {
	return s.trust.Reload(ctx)
}

// ensureTrust loads the trusted lists after a failed load. Its error names no
// URL. The cause names the internal wallet URL and goes to the log.
func (s *Server) ensureTrust(ctx context.Context) error {
	if _, err := s.trust.Summary(); err == nil {
		return nil
	}
	if err := s.trust.Reload(ctx); err != nil {
		log.Printf("loading the trusted lists: %v", err)
		return errors.New("the trusted lists of the wallet did not load")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("writing a response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": message})
}

// readWalletResponse parses a direct_post body of at most maxResponseBytes.
func readWalletResponse(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxResponseBytes)
	err := r.ParseForm()
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", fmt.Sprintf("the response is larger than the limit of %d bytes", tooLarge.Limit))
		return false
	case err != nil:
		writeError(w, http.StatusBadRequest, "invalid_request", "the response body does not parse: "+err.Error())
		return false
	}
	return true
}

func randomID() string {
	raw := make([]byte, 18)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func readJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	body := http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(body).Decode(into); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "the body is not valid JSON")
		return false
	}
	return true
}

// loopback serves requests for the public base URL in this process. The
// agent and the verifiers share the server, and the public URL may be
// reachable only through a reverse proxy.
type loopback struct {
	prefix  string
	handler http.Handler
}

func (l loopback) RoundTrip(request *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(request.URL.String(), l.prefix+"/") {
		return nil, errors.New("the agent only calls verifiers of this demo")
	}
	recorder := httptest.NewRecorder()
	l.handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}
