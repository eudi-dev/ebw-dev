package demo

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/ebw-dev/internal/dsdjwt"
	"github.com/eudi-dev/ebw-dev/internal/trust"
)

const TypeEBWOID = "uri:eu.ebw.oid.1"

const (
	ScenarioPending  = "pending"
	ScenarioAccepted = "accepted"
	ScenarioRefused  = "refused"
)

const (
	VariantWrongScope = "wrong_scope"
)

// Policy checks of the scenarios. Each one goes into the report of the
// checked credential.
const (
	CheckPolicyScope      = "policy_poa_scope"
	CheckPolicyValidity   = "policy_poa_validity"
	CheckPolicyIdentifier = "policy_kyb_identifier"
	CheckPolicyName       = "policy_kyb_name"
)

// Powers of the EU PoA rulebook, quoted from its list of powers.
const (
	powerBranches = "Registration and closure of branches of the Company"
	powerMergers  = "All legal transactions regarding cross border mergers involving the Company"
)

// Query is one credential query of a scenario request (OpenID4VP 1.0 §6.1).
type Query struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	// Template is the credential template of the wallet for the type.
	Template string  `json:"template"`
	Claims   [][]any `json:"claims"`
}

type ScenarioVariant struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Expectation string `json:"expectation"`
}

type ScenarioVerifier struct {
	Name         string `json:"name"`
	Organisation string `json:"organisation"`
	Country      string `json:"country"`
}

// Scenario is a verifier that asks the business wallet for a plain
// presentation of one or more credentials.
type Scenario struct {
	ID       string           `json:"id"`
	Title    string           `json:"title"`
	Intro    string           `json:"intro"`
	Verifier ScenarioVerifier `json:"verifier"`
	// Task is what the verifier does once the presentation holds.
	Task         string            `json:"task"`
	Queries      []Query           `json:"queries"`
	TrustedLists []string          `json:"trusted_lists"`
	Variants     []ScenarioVariant `json:"variants"`

	// Kind is the verifier in one word, for the breadcrumbs and the map.
	Kind string `json:"-"`
	// Asker is the verifier as the subject of a sentence.
	Asker string `json:"-"`
	// Short is the verifier name in the progress rail.
	Short   string `json:"-"`
	Summary string `json:"-"`
	Ask     string `json:"-"`
	AskText string `json:"-"`
	Check   string `json:"-"`
	// Accepted is the result line after the verifier accepted.
	Accepted string `json:"-"`
	// Done is the progress rail line after the verifier accepted.
	Done string `json:"-"`

	party       relyingParty
	intendedUse string
	policy      func(request *ScenarioRequest, presented map[string]*dsdjwt.Report, now time.Time)
}

var poaQuery = Query{
	ID: "poa", Name: "EU power of attorney", Type: TypePowerOfAttorney, Template: "eu-poa",
	Claims: [][]any{
		{"euid_reference"}, {"company_statutory_full_name"}, {"attorney_full_name"},
		{"scope_of_representation_powers", nil}, {"validity_period_valid_from"}, {"validity_period_valid_until"},
	},
}

var scenarios = []Scenario{
	{
		ID:    "poa",
		Title: "Power of attorney at a notary",
		Intro: "Alice registers a branch of Acme Logistics GmbH in Rotterdam. Delta Notaries asks the business wallet for the EU power of attorney. The notary checks that her powers cover the registration.",
		Verifier: ScenarioVerifier{
			Name: "Delta notary desk", Organisation: "Delta Notaries B.V.", Country: "NL",
		},
		Task:         "Registration of the Rotterdam branch of Acme Logistics GmbH",
		Queries:      []Query{poaQuery},
		TrustedLists: []string{"pub-eaa", "qeaa"},
		Variants: []ScenarioVariant{
			{ID: VariantOK, Title: "Branch registration", Expectation: "The notary accepts the power of attorney for the branch registration."},
			{ID: VariantWrongScope, Title: "Power outside the scope", Expectation: "The notary asks for a cross border merger. Alice's powers do not include mergers."},
			{ID: VariantExpired, Title: "Expired power of attorney", Expectation: "The registration is one day after the power of attorney ends."},
			{ID: VariantRevoked, Title: "Revoked power of attorney", Expectation: "The issuer revokes the power of attorney before the notary checks it."},
		},
		Kind: "Notary", Asker: "The notary", Short: "Delta Notaries",
		Summary:     "Checks the power of attorney of Alice for a branch registration.",
		Ask:         "The notary asks the wallet",
		AskText:     "The notary asks for the EU power of attorney of Acme for a branch registration.",
		Check:       "The notary checks the powers",
		Accepted:    "The notary accepted the power of attorney.",
		Done:        "Accepted",
		party:       relyingParty{ID: "NLTEST.00000473", Service: "notary-desk", Name: "Delta notary desk"},
		intendedUse: "branch-registration",
		policy:      poaPolicy,
	},
	{
		ID:    "kyb",
		Title: "Know your business at a bank",
		Intro: "Acme Logistics GmbH opens a business account at Example Bank. The bank asks for 2 credentials in one request. It checks that both show the same company.",
		Verifier: ScenarioVerifier{
			Name: "Example Bank business onboarding", Organisation: "Example Bank AB", Country: "SE",
		},
		Task: "Opening of a business account for Acme Logistics GmbH",
		Queries: []Query{
			{
				ID: "ebwoid", Name: "Business wallet owner identification data", Type: TypeEBWOID, Template: "ebwoid",
				Claims: [][]any{{"id"}, {"name"}, {"issuing_authority"}, {"issuing_country"}, {"date_of_expiry"}},
			},
			poaQuery,
		},
		TrustedLists: []string{"pub-eaa", "qeaa"},
		Variants: []ScenarioVariant{
			{ID: VariantOK, Title: "Account opening", Expectation: "The bank accepts both credentials and shows the company data."},
		},
		Kind: "Bank", Asker: "The bank", Short: "Example Bank",
		Summary:     "Checks the company before it opens a business account.",
		Ask:         "The bank asks the wallet",
		AskText:     "The bank asks for the owner identification data and the EU power of attorney of Acme.",
		Check:       "The bank checks the company",
		Accepted:    "The bank accepted both credentials.",
		Done:        "Account opened",
		party:       relyingParty{ID: "SETEST.00000474", Service: "business-onboarding", Name: "Example Bank business onboarding"},
		intendedUse: "know-your-business",
		policy:      kybPolicy,
	},
}

func scenarioByID(id string) (Scenario, bool) {
	index := slices.IndexFunc(scenarios, func(s Scenario) bool { return s.ID == id })
	if index < 0 {
		return Scenario{}, false
	}
	return scenarios[index], true
}

// ScenarioRequest is one request of a scenario verifier with the answer of the
// wallet.
type ScenarioRequest struct {
	ID       string    `json:"id"`
	Scenario string    `json:"scenario"`
	Variant  string    `json:"variant"`
	Status   string    `json:"status"`
	Created  time.Time `json:"created"`
	// Power is the power of the EU PoA rulebook that the registration needs.
	Power string `json:"power,omitempty"`
	// TaskDate is the date of the registration. The notary checks the
	// validity period of the power of attorney against it.
	TaskDate          string         `json:"task_date,omitempty"`
	Request           MandateRequest `json:"request"`
	RequestDecoderURL string         `json:"request_decoder_url"`
	// Error and ErrorDescription come from the wallet when it answers with
	// an OpenID4VP error (OpenID4VP 1.0 §8.5).
	Error            string                 `json:"error,omitempty"`
	ErrorDescription string                 `json:"error_description,omitempty"`
	Reasons          []string               `json:"reasons"`
	Presentations    []ScenarioPresentation `json:"presentations"`
	Learned          []Fact                 `json:"learned"`
	// Notes are the changes of the demo to the wallet, such as a revocation.
	Notes []string `json:"notes"`

	answerState
	nonce    string
	clientID string
}

type ScenarioPresentation struct {
	Query      string         `json:"query"`
	Name       string         `json:"name"`
	Token      string         `json:"token"`
	DecoderURL string         `json:"decoder_url"`
	Report     *dsdjwt.Report `json:"report"`
}

type Fact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (s *Server) decoderURL(value string) string {
	return s.config.WalletPublicURL + "/decoder/#credential=" + url.QueryEscape(value)
}

func (s *Server) createScenarioRequest(w http.ResponseWriter, r *http.Request) {
	scenario, ok := scenarioByID(r.PathValue("scenario"))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown_scenario", "there is no scenario with this id")
		return
	}
	var body struct {
		Variant string `json:"variant"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Variant == "" {
		body.Variant = VariantOK
	}
	if !slices.ContainsFunc(scenario.Variants, func(v ScenarioVariant) bool { return v.ID == body.Variant }) {
		writeError(w, http.StatusBadRequest, "unknown_variant", "this scenario has no variant "+body.Variant)
		return
	}
	now := s.now().Truncate(time.Second)
	request := &ScenarioRequest{
		ID: randomID(), Scenario: scenario.ID, Variant: body.Variant, Status: ScenarioPending, Created: now,
		Reasons: []string{}, Presentations: []ScenarioPresentation{}, Learned: []Fact{}, Notes: []string{},
		answerState: answerState{state: randomID()}, nonce: randomID(),
	}
	if scenario.ID == "poa" {
		request.Power = powerBranches
		if body.Variant == VariantWrongScope {
			request.Power = powerMergers
		}
	}
	if err := s.prepareWallet(r.Context(), scenario, request); err != nil {
		writeError(w, http.StatusBadGateway, "wallet_unavailable", err.Error())
		return
	}
	registration, verifierInfo, err := s.registered(r.Context(), scenario.party, scenario.intendedUse)
	if err != nil {
		writeError(w, http.StatusBadGateway, "registration_failed", err.Error())
		return
	}
	request.clientID = registration.clientID
	credentials := make([]any, 0, len(scenario.Queries))
	for _, query := range scenario.Queries {
		credentials = append(credentials, credentialQuery(query.ID, []string{query.Type}, query.Claims))
	}
	claims := map[string]any{
		"response_type":   "vp_token",
		"response_mode":   "direct_post",
		"response_uri":    s.url("/scenarios/" + scenario.ID + "/response"),
		"nonce":           request.nonce,
		"state":           request.state,
		"dcql_query":      map[string]any{"credentials": credentials},
		"client_metadata": clientMetadata,
		"verifier_info":   verifierInfo,
	}
	requestObject, err := registration.requestObject(claims, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	encoded := encodeQuery(url.Values{"client_id": {registration.clientID}, "request": {requestObject}})
	decoded := maps.Clone(claims)
	decoded["client_id"] = registration.clientID
	request.Request = MandateRequest{
		WalletURL:     s.config.WalletPublicURL + "/authorize?" + encoded,
		URI:           "openid4vp://authorize?" + encoded,
		RequestObject: requestObject,
		Decoded:       decoded,
	}
	request.RequestDecoderURL = s.decoderURL(request.Request.URI)

	s.mu.Lock()
	s.prune(now)
	s.scenarioRequests[request.ID] = request
	snapshot := request.snapshot()
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, snapshot)
}

func (s *Server) prepareWallet(ctx context.Context, scenario Scenario, request *ScenarioRequest) error {
	for _, query := range scenario.Queries {
		issued, err := s.ensureValid(ctx, query.Type, query.Template)
		if err != nil {
			return err
		}
		if issued {
			request.Notes = append(request.Notes, "The wallet had no valid "+query.Name+". The demo issued a new one.")
		}
	}
	return nil
}

// revokeBeforeStatus wraps a status checker for the revoked variant. It
// revokes the presented credential in the wallet before the check. Other
// credentials in a shared wallet stay valid.
func (s *Server) revokeBeforeStatus(ctx context.Context, request *ScenarioRequest, check func(map[string]any) error) func(map[string]any) error {
	return func(claims map[string]any) error {
		uri, index, err := trust.StatusReference(claims)
		if err != nil {
			return check(claims)
		}
		_, revoked, err := s.revokeInWallet(ctx, uri, index)
		if err != nil {
			return fmt.Errorf("revoking the presented credential failed: %w", err)
		}
		if revoked {
			request.Notes = append(request.Notes, "The issuer revoked the EU power of attorney before the notary checked it.")
		}
		return check(claims)
	}
}

func (r *ScenarioRequest) snapshot() ScenarioRequest {
	copied := *r
	copied.Reasons = slices.Clone(r.Reasons)
	copied.Presentations = slices.Clone(r.Presentations)
	copied.Learned = slices.Clone(r.Learned)
	copied.Notes = slices.Clone(r.Notes)
	return copied
}

func (s *Server) getScenarioRequest(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	request, ok := s.scenarioRequests[r.PathValue("id")]
	var snapshot ScenarioRequest
	if ok && request.Scenario == r.PathValue("scenario") {
		snapshot = request.snapshot()
	} else {
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "unknown_request", "there is no request with this id")
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) scenarioResponse(w http.ResponseWriter, r *http.Request) {
	if !readWalletResponse(w, r) {
		return
	}
	request, ok := claimAnswer(s, s.scenarioRequests, r.PostFormValue("state"), func(candidate *ScenarioRequest) bool {
		return candidate.Scenario == r.PathValue("scenario") && candidate.Status == ScenarioPending
	})
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", "no open request matches this state")
		return
	}
	s.mu.Lock()
	answer := request.snapshot()
	s.mu.Unlock()

	scenario, _ := scenarioByID(answer.Scenario)
	s.checkScenarioAnswer(r, scenario, &answer)
	if answer.Variant == VariantRevoked {
		if issued, err := s.ensureValid(r.Context(), TypePowerOfAttorney, poaQuery.Template); err != nil {
			answer.Notes = append(answer.Notes, "The demo could not issue a new EU power of attorney: "+err.Error()+".")
		} else if issued {
			answer.Notes = append(answer.Notes, "The demo issued a new EU power of attorney for the next request.")
		}
	}
	answer.checking = false
	s.mu.Lock()
	*request = answer
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{
		"redirect_uri": s.url("/scenarios/" + scenario.ID + "?request=" + url.QueryEscape(answer.ID)),
	})
}

func (s *Server) checkScenarioAnswer(r *http.Request, scenario Scenario, request *ScenarioRequest) {
	request.Status = ScenarioRefused
	if code := r.PostFormValue("error"); code != "" {
		request.Error, request.ErrorDescription = code, r.PostFormValue("error_description")
		request.Reasons = append(request.Reasons, "The wallet returned the error "+code+".")
		return
	}
	tokens, err := vpTokens(r)
	if err != nil {
		request.Reasons = append(request.Reasons, sentence(err.Error()))
		return
	}
	if err := s.ensureTrust(r.Context()); err != nil {
		request.Reasons = append(request.Reasons, "The trusted lists of the wallet did not load: "+err.Error()+".")
		return
	}
	now := s.now()
	options := dsdjwt.Options{
		Now:           now,
		ResolveIssuer: s.trust.ResolveIssuer(scenario.TrustedLists, now),
		CheckStatus:   s.trust.CheckStatus(r.Context(), scenario.TrustedLists, now),
	}
	presented := map[string]*dsdjwt.Report{}
	for _, query := range scenario.Queries {
		if len(tokens[query.ID]) != 1 {
			request.Reasons = append(request.Reasons, fmt.Sprintf("The wallet sent %d presentations of the %s. The verifier expects one.", len(tokens[query.ID]), query.Name))
			continue
		}
		token := tokens[query.ID][0]
		queryOptions := options
		if request.Variant == VariantRevoked && query.Type == TypePowerOfAttorney {
			queryOptions.CheckStatus = s.revokeBeforeStatus(r.Context(), request, options.CheckStatus)
		}
		report, err := dsdjwt.VerifySDJWT(token, dsdjwt.SDJWTExpectation{Audience: request.clientID, Nonce: request.nonce}, queryOptions)
		if err != nil {
			request.Reasons = append(request.Reasons, sentence(err.Error()))
			continue
		}
		if link := report.Link(dsdjwt.LinkCredential); link != nil && report.Credential != nil {
			vct, _ := report.Credential["vct"].(string)
			var mismatch error
			if vct != query.Type {
				mismatch = fmt.Errorf("the %s has the type %s", query.Name, vct)
			}
			link.Add(dsdjwt.CheckPolicyType, mismatch, vct)
		}
		presented[query.ID] = report
		request.Presentations = append(request.Presentations, ScenarioPresentation{
			Query: query.ID, Name: query.Name, Token: token, DecoderURL: s.decoderURL(token), Report: report,
		})
	}
	if len(request.Reasons) > 0 {
		return
	}
	scenario.policy(request, presented, now)
	for _, presentation := range request.Presentations {
		presentation.Report.Seal()
		for _, check := range presentation.Report.FailedChecks() {
			request.Reasons = append(request.Reasons, sentence(check.Detail))
		}
	}
	if len(request.Reasons) == 0 {
		request.Status = ScenarioAccepted
	}
}

func claimText(claims map[string]any, name string) string {
	value, _ := claims[name].(string)
	return value
}

func claimList(claims map[string]any, name string) []string {
	values, _ := claims[name].([]any)
	texts := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			texts = append(texts, text)
		}
	}
	return texts
}

// poaPolicy checks the powers and the validity period of the EU PoA (EU PoA
// rulebook v0.2). The variant expired moves the registration to the day after
// the end of the validity period.
func poaPolicy(request *ScenarioRequest, presented map[string]*dsdjwt.Report, now time.Time) {
	report := presented[poaQuery.ID]
	link := report.Link(dsdjwt.LinkCredential)
	if link == nil || report.Credential == nil {
		return
	}
	claims := report.Credential
	powers := claimList(claims, "scope_of_representation_powers")
	var scopeErr error
	if !slices.Contains(powers, request.Power) {
		scopeErr = fmt.Errorf("the power of attorney does not include %q", request.Power)
	}
	link.Add(CheckPolicyScope, scopeErr, request.Power)

	from, until := claimText(claims, "validity_period_valid_from"), claimText(claims, "validity_period_valid_until")
	date := now.UTC()
	var validityErr error
	if request.Variant == VariantExpired {
		end, err := time.Parse(time.DateOnly, until)
		if err != nil {
			validityErr = fmt.Errorf("validity_period_valid_until %q is not a date of the form YYYY-MM-DD", until)
		} else {
			date = end.AddDate(0, 0, 1)
		}
	}
	request.TaskDate = date.Format(time.DateOnly)
	if validityErr == nil {
		validityErr = withinValidity(request.TaskDate, from, until)
	}
	link.Add(CheckPolicyValidity, validityErr, "valid on "+request.TaskDate)

	request.Learned = append(request.Learned,
		Fact{"Company", claimText(claims, "company_statutory_full_name")},
		Fact{"EUID", claimText(claims, "euid_reference")},
		Fact{"Representative", claimText(claims, "attorney_full_name")},
		Fact{"Powers", strings.Join(powers, ". ")},
		Fact{"Valid period", validityText(from, until)},
	)
}

// withinValidity compares dates of the form YYYY-MM-DD. Without
// validity_period_valid_until the power of attorney has no end (EU PoA
// rulebook v0.2, IR-02).
func withinValidity(date, from, until string) error {
	for _, bound := range []struct{ claim, value string }{{"validity_period_valid_from", from}, {"validity_period_valid_until", until}} {
		if _, err := time.Parse(time.DateOnly, bound.value); bound.value != "" && err != nil {
			return fmt.Errorf("%s %q is not a date of the form YYYY-MM-DD", bound.claim, bound.value)
		}
	}
	if from != "" && date < from {
		return fmt.Errorf("the power of attorney is valid from %s and the registration is on %s", from, date)
	}
	if until != "" && date > until {
		return fmt.Errorf("the power of attorney ended on %s and the registration is on %s", until, date)
	}
	return nil
}

func validityText(from, until string) string {
	switch {
	case from == "" && until == "":
		return "No validity period"
	case until == "":
		return "From " + from + " without an end date"
	case from == "":
		return "Until " + until
	}
	return "From " + from + " until " + until
}

// kybPolicy checks that the owner identification data and the power of
// attorney show the same company.
func kybPolicy(request *ScenarioRequest, presented map[string]*dsdjwt.Report, _ time.Time) {
	owner, poa := presented["ebwoid"].Credential, presented[poaQuery.ID].Credential
	link := presented[poaQuery.ID].Link(dsdjwt.LinkCredential)
	if owner == nil || poa == nil || link == nil {
		return
	}
	id, name := claimText(owner, "id"), claimText(owner, "name")
	link.Add(CheckPolicyIdentifier, sameValue("identifier", id, claimText(poa, "euid_reference")), id)
	link.Add(CheckPolicyName, sameValue("name", name, claimText(poa, "company_statutory_full_name")), name)
	request.Learned = append(request.Learned,
		Fact{"Company", name},
		Fact{"Identifier", id},
		Fact{"Register", claimText(owner, "issuing_authority")},
		Fact{"Country", claimText(owner, "issuing_country")},
		Fact{"Owner data valid until", claimText(owner, "date_of_expiry")},
		Fact{"Representative", claimText(poa, "attorney_full_name")},
		Fact{"Powers", strings.Join(claimList(poa, "scope_of_representation_powers"), ". ")},
		Fact{"Power of attorney valid", validityText(claimText(poa, "validity_period_valid_from"), claimText(poa, "validity_period_valid_until"))},
	)
}

func sameValue(name, owner, poa string) error {
	switch {
	case owner == "":
		return fmt.Errorf("the owner identification data discloses no company %s", name)
	case owner != poa:
		return fmt.Errorf("the company %s is %q in the owner identification data and %q in the power of attorney", name, owner, poa)
	}
	return nil
}

// Refusals are the variants of a scenario that the verifier has to refuse.
func (s Scenario) Refusals() []ScenarioVariant {
	refusals := make([]ScenarioVariant, 0, len(s.Variants))
	for _, variant := range s.Variants {
		if variant.ID != VariantOK {
			refusals = append(refusals, variant)
		}
	}
	return refusals
}
