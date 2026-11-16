package demo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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

const (
	MandatePending = "pending"
	MandateGranted = "granted"
	MandateRefused = "refused"
)

const ErrorNoDelegation = "wallet_without_delegation"

const (
	credentialQueryID = "authority"
	// maxEntries bounds each in-memory store of the server.
	maxEntries        = 200
	maxRunsPerMandate = 50
	// maxResponseBytes limits a wallet response. A presentation with its
	// x5c chains is about 10 KiB.
	maxResponseBytes = 64 << 10
)

var authorityLists = []string{"pub-eaa", "qeaa", "eaa"}

type Mandate struct {
	ID     string `json:"id"`
	Case   string `json:"case"`
	Status string `json:"status"`
	// Error and ErrorDescription say why the delegation was refused. They
	// come from the wallet when it answers with an OpenID4VP error
	// (OpenID4VP 1.0 §8.5).
	Error            string         `json:"error,omitempty"`
	ErrorDescription string         `json:"error_description,omitempty"`
	Created          time.Time      `json:"created"`
	Expires          time.Time      `json:"expires"`
	AgentKey         string         `json:"agent_key_thumbprint"`
	Request          MandateRequest `json:"request"`
	Token            string         `json:"token,omitempty"`
	Report           *dsdjwt.Report `json:"report,omitempty"`
	Runs             []string       `json:"runs"`

	answerState
	nonce    string
	clientID string
	key      *ecdsa.PrivateKey
	sent     dsdjwt.TransactionData
	// activeRuns counts runs that have not finished. They count against
	// maxRunsPerMandate, so parallel requests can't exceed it.
	activeRuns int
}

type MandateRequest struct {
	WalletURL string `json:"wallet_url"`
	URI       string `json:"openid4vp_uri"`
	// RequestObject is the signed request (OpenID4VP 1.0 §5, RFC 9101).
	RequestObject string         `json:"request_object"`
	Decoded       map[string]any `json:"decoded"`
}

func encodeQuery(params url.Values) string {
	// The wallet reads + in a query as a literal plus sign.
	return strings.ReplaceAll(params.Encode(), "+", "%20")
}

func compactJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}

// credentialQuery is a DCQL credential query for an SD-JWT VC (OpenID4VP 1.0
// §6.1).
func credentialQuery(id string, types []string, claims [][]any) map[string]any {
	credential := map[string]any{
		"id":     id,
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": types},
	}
	if len(claims) > 0 {
		paths := make([]any, 0, len(claims))
		for _, path := range claims {
			paths = append(paths, map[string]any{"path": path})
		}
		credential["claims"] = paths
	}
	return credential
}

// answerState is the state of an OpenID4VP request. checking is set while an
// answer is checked, so a second answer with the same state finds no open
// request.
type answerState struct {
	state    string
	checking bool
}

func (a *answerState) answer() *answerState { return a }

// claimAnswer finds the open request for the state of a direct_post answer and
// marks it as being checked.
func claimAnswer[T interface{ answer() *answerState }](s *Server, requests map[string]T, state string, open func(T) bool) (T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, request := range requests {
		if a := request.answer(); a.state == state && !a.checking && open(request) {
			a.checking = true
			return request, true
		}
	}
	var none T
	return none, false
}

const mandateLifetime = time.Hour

// expiredShift is the clock shift of the expired mandate run. It lies past
// the end of every mandate.
const expiredShift = mandateLifetime + 5*time.Minute

var clientMetadata = map[string]any{
	"vp_formats_supported": map[string]any{
		"dc+sd-jwt": map[string]any{
			"sd-jwt_alg_values": []string{"ES256"},
			"kb-jwt_alg_values": []string{"ES256"},
		},
	},
}

func (s *Server) createMandate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Case string `json:"case"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	selected, ok := caseByID(body.Case)
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown_case", "case must be supplier or internal")
		return
	}
	registration, verifierInfo, err := s.registered(r.Context(), agentService, selected.IntendedUse)
	if err != nil {
		writeError(w, http.StatusBadGateway, "registration_failed", err.Error())
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	agentKey, _ := dsdjwt.PublicJWK(&key.PublicKey)
	now := s.now().Truncate(time.Second)
	mandate := &Mandate{
		ID:          randomID(),
		Case:        selected.ID,
		Status:      MandatePending,
		Created:     now,
		Expires:     now.Add(mandateLifetime),
		AgentKey:    agentKey.Thumbprint(),
		Runs:        []string{},
		answerState: answerState{state: randomID()},
		nonce:       randomID(),
		clientID:    registration.clientID,
		key:         key,
	}
	delegatePayload := dsdjwt.Mandate{
		IssuedAt:  mandate.Created,
		Expires:   mandate.Expires,
		AgentKey:  agentKey,
		Agent:     selected.Agent,
		Purpose:   selected.Purpose,
		Actions:   []string{selected.Action},
		Limit:     selected.Limit,
		Audiences: []string{s.verifierClientID(selected.Verifier), selected.OtherAudience},
	}
	mandate.sent, err = dsdjwt.NewTransactionData(delegatePayload, []string{credentialQueryID})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	claims := map[string]any{
		"response_type":    "vp_token",
		"response_mode":    "direct_post",
		"response_uri":     s.url("/agent/response"),
		"nonce":            mandate.nonce,
		"state":            mandate.state,
		"dcql_query":       map[string]any{"credentials": []any{credentialQuery(credentialQueryID, []string{selected.CredentialType}, selected.Claims)}},
		"transaction_data": []string{mandate.sent.Encoded},
		"client_metadata":  clientMetadata,
		"verifier_info":    verifierInfo,
	}
	requestObject, err := registration.requestObject(claims, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	encoded := encodeQuery(url.Values{"client_id": {registration.clientID}, "request": {requestObject}})
	walletURL := s.config.WalletPublicURL + "/authorize?" + encoded
	decoded := maps.Clone(claims)
	decoded["client_id"] = registration.clientID
	decoded["transaction_data"] = []any{mandate.sent.Decoded}
	mandate.Request = MandateRequest{
		WalletURL:     walletURL,
		URI:           "openid4vp://authorize?" + encoded,
		RequestObject: requestObject,
		Decoded:       decoded,
	}

	s.mu.Lock()
	s.prune(now)
	s.mandates[mandate.ID] = mandate
	snapshot := *mandate
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, snapshot)
}

// prune keeps the stores of the server small. A mandate stays one hour after
// its end. The caller holds the lock.
func (s *Server) prune(now time.Time) {
	pruneStore(s.mandates, func(m *Mandate) time.Time { return m.Created }, now, mandateLifetime+time.Hour, func(id string) {
		for _, run := range s.mandates[id].Runs {
			delete(s.runs, run)
		}
		delete(s.mandates, id)
	})
	pruneStore(s.requests, func(r *verifierRequest) time.Time { return r.created }, now, 10*time.Minute, func(id string) {
		delete(s.requests, id)
	})
	pruneStore(s.scenarioRequests, func(r *ScenarioRequest) time.Time { return r.Created }, now, time.Hour, func(id string) {
		delete(s.scenarioRequests, id)
	})
}

// pruneStore drops the entries older than maxAge and then the oldest entries
// until there is room for one more. drop must delete the entry from the store.
func pruneStore[T any](store map[string]T, created func(T) time.Time, now time.Time, maxAge time.Duration, drop func(id string)) {
	for id, entry := range store {
		if now.Sub(created(entry)) > maxAge {
			drop(id)
		}
	}
	for len(store) >= maxEntries {
		oldest := ""
		for id, entry := range store {
			if oldest == "" || created(entry).Before(created(store[oldest])) {
				oldest = id
			}
		}
		drop(oldest)
	}
}

func (s *Server) getMandate(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	mandate, ok := s.mandates[r.PathValue("id")]
	var snapshot Mandate
	if ok {
		snapshot = *mandate
		snapshot.Runs = slices.Clone(mandate.Runs)
	}
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "unknown_mandate", "there is no delegation with this id")
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

// vpToken reads the presentation of one credential query from a direct_post
// body (OpenID4VP 1.0 §8.1).
func vpToken(r *http.Request, queryID string) (string, error) {
	tokens, err := vpTokens(r)
	if err != nil {
		return "", err
	}
	presentations := tokens[queryID]
	if len(presentations) != 1 {
		return "", fmt.Errorf("vp_token needs one presentation for the query %q", queryID)
	}
	return presentations[0], nil
}

// vpTokens reads the vp_token of a direct_post body. It maps each credential
// query id to its presentations (OpenID4VP 1.0 §8.1).
func vpTokens(r *http.Request) (map[string][]string, error) {
	var tokens map[string][]string
	if err := json.Unmarshal([]byte(r.PostFormValue("vp_token")), &tokens); err != nil {
		return nil, errors.New("vp_token is not a JSON object of presentation arrays")
	}
	return tokens, nil
}

func (s *Server) agentResponse(w http.ResponseWriter, r *http.Request) {
	if !readWalletResponse(w, r) {
		return
	}
	mandate, ok := claimAnswer(s, s.mandates, r.PostFormValue("state"), func(m *Mandate) bool { return m.Status == MandatePending })
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", "no open delegation request matches this state")
		return
	}

	answer := s.receiveMandate(r, mandate)
	s.mu.Lock()
	mandate.Status, mandate.Error, mandate.ErrorDescription = answer.status, answer.code, answer.message
	mandate.Token, mandate.Report, mandate.checking = answer.token, answer.report, false
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{
		"redirect_uri": s.url("/cases/" + mandate.Case + "?mandate=" + url.QueryEscape(mandate.ID)),
	})
}

type mandateAnswer struct {
	status, code, message, token string
	report                       *dsdjwt.Report
}

func refusal(code, message, token string, report *dsdjwt.Report) mandateAnswer {
	return mandateAnswer{status: MandateRefused, code: code, message: message, token: token, report: report}
}

func (s *Server) receiveMandate(r *http.Request, mandate *Mandate) mandateAnswer {
	if code := r.PostFormValue("error"); code != "" {
		description := r.PostFormValue("error_description")
		if description == "" {
			description = "The wallet returned the error " + code + "."
		}
		return refusal(code, description, "", nil)
	}
	token, err := vpToken(r, credentialQueryID)
	if err != nil {
		return refusal("invalid_response", "The answer of the wallet is not usable: "+err.Error()+".", "", nil)
	}
	if err := s.ensureTrust(r.Context()); err != nil {
		return refusal("trust_unavailable", sentence(err.Error()), token, nil)
	}
	now := s.now()
	selected, _ := caseByID(mandate.Case)
	report, err := dsdjwt.VerifyMandate(token, dsdjwt.MandateExpectation{
		Audience: mandate.clientID,
		Nonce:    mandate.nonce,
		Sent:     mandate.sent,
	}, dsdjwt.Options{
		Now:           now,
		ResolveIssuer: s.trust.ResolveIssuer(authorityLists, now),
		CheckStatus:   s.trust.CheckStatus(r.Context(), authorityLists, now),
	})
	switch {
	case errors.Is(err, dsdjwt.ErrNoDelegation):
		return refusal(ErrorNoDelegation,
			"This wallet does not support delegation. It answered with a plain SD-JWT presentation and signed no delegation for the agent.", token, report)
	case err != nil:
		return refusal("invalid_response", "The answer of the wallet is not a delegation chain: "+err.Error()+".", token, report)
	}
	if link := report.Link(dsdjwt.LinkCredential); link != nil && report.Credential != nil {
		var mismatch error
		if vct, _ := report.Credential["vct"].(string); vct != selected.CredentialType {
			mismatch = fmt.Errorf("the credential type %q is not %q", vct, selected.CredentialType)
		}
		link.Add(dsdjwt.CheckPolicyType, mismatch, "")
		report.Seal()
	}
	if !report.Valid {
		return refusal("mandate_invalid", "The delegation failed these checks: "+strings.Join(checkNames(report.FailedChecks()), ", ")+".", token, report)
	}
	return mandateAnswer{status: MandateGranted, token: token, report: report}
}

type Step struct {
	// Actor is agent, verifier or wallet. Wallet steps change the business
	// wallet through its API.
	Actor  string `json:"actor"`
	Text   string `json:"text"`
	Detail any    `json:"detail,omitempty"`
}

type Run struct {
	ID       string    `json:"id"`
	Mandate  string    `json:"mandate"`
	Case     string    `json:"case"`
	Variant  string    `json:"variant"`
	Verifier Verifier  `json:"verifier"`
	Created  time.Time `json:"created"`
	Steps    []Step    `json:"steps"`
	// Outcome is accepted, refused, failed or stopped. Failed means the run
	// broke before the verifier decided. Stopped means the demo ended the run
	// before the agent acted. Reasons explain why.
	Outcome string         `json:"outcome"`
	Reasons []string       `json:"reasons"`
	Token   string         `json:"token,omitempty"`
	Report  *dsdjwt.Report `json:"report,omitempty"`
}

func (run *Run) log(actor, text string, detail any) {
	run.Steps = append(run.Steps, Step{Actor: actor, Text: text, Detail: detail})
}

func (s *Server) createRun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Variant string `json:"variant"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Variant == "" {
		body.Variant = VariantOK
	}
	if !slices.Contains(variants, body.Variant) {
		writeError(w, http.StatusBadRequest, "unknown_variant", "variant must be one of "+strings.Join(variants, ", "))
		return
	}
	s.mu.Lock()
	mandate, ok := s.mandates[r.PathValue("id")]
	var snapshot Mandate
	switch {
	case !ok:
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "unknown_mandate", "there is no delegation with this id")
		return
	case mandate.Status != MandateGranted:
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "no_mandate", "the agent has no delegation yet")
		return
	case len(mandate.Runs)+mandate.activeRuns >= maxRunsPerMandate:
		s.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "too_many_runs", "this delegation has no runs left")
		return
	}
	mandate.activeRuns++
	snapshot = *mandate
	s.mu.Unlock()

	run := s.runAgent(r.Context(), &snapshot, body.Variant)
	s.mu.Lock()
	mandate.activeRuns--
	if s.mandates[mandate.ID] == mandate {
		mandate.Runs = append(mandate.Runs, run.ID)
		s.runs[run.ID] = run
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, run)
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	run, ok := s.runs[r.PathValue("id")]
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "unknown_run", "there is no run with this id")
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// runAgent executes the fixed task of the case. A refusal variant changes
// exactly one input.
func (s *Server) runAgent(ctx context.Context, mandate *Mandate, variant string) *Run {
	selected, _ := caseByID(mandate.Case)
	verifier := verifiers[selected.Verifier]
	if variant == VariantWrongVerifier {
		verifier = verifiers[strangerID]
	}
	run := &Run{
		ID: randomID(), Mandate: mandate.ID, Case: selected.ID, Variant: variant,
		Verifier: verifier, Created: s.now(), Steps: []Step{}, Reasons: []string{},
	}
	var err error
	if variant == VariantRevoked {
		var stopped bool
		if stopped, err = s.revoke(ctx, run, mandate, selected); stopped {
			return run
		}
	}
	if err == nil {
		err = s.act(ctx, run, mandate, selected, verifier)
	}
	if err != nil {
		run.Outcome = "failed"
		run.Reasons = []string{err.Error()}
		run.log("agent", "The agent stopped: "+err.Error()+".", nil)
	}
	if variant == VariantRevoked {
		issued, err := s.ensureValid(ctx, selected.CredentialType, selected.Template, false)
		switch {
		case err != nil:
			run.log("wallet", "The wallet issued no new credential: "+err.Error()+".", nil)
		case issued:
			run.log("wallet", "Issues a new "+selected.CredentialName+". Verifiers refuse the revoked delegation. The next delegation uses the new credential.", nil)
		}
	}
	return run
}

// revoke sets the Token Status List entry of the credential under the delegation
// to 1 (draft-ietf-oauth-status-list-21 §7.1). When the credential is
// protected, it stops the run. The next delegation rests on a new credential.
func (s *Server) revoke(ctx context.Context, run *Run, mandate *Mandate, selected Case) (bool, error) {
	uri, index, err := trust.StatusReference(mandate.Report.Credential)
	if err != nil {
		return false, fmt.Errorf("the credential under the delegation: %w", err)
	}
	held, err := s.heldCredential(ctx, uri, index)
	if err != nil {
		return false, err
	}
	detail := map[string]any{"uri": uri, "idx": index}
	if held.Protected {
		if _, err := s.ensureValid(ctx, selected.CredentialType, selected.Template, true); err != nil {
			return false, err
		}
		run.Outcome = "stopped"
		run.Reasons = []string{"The credential behind this delegation is a protected Acme credential of the demo. The demo cannot revoke it. The wallet holds a new " + selected.CredentialName + " for the next delegation. Start again for a new delegation."}
		run.log("wallet", run.Reasons[0], detail)
		return true, nil
	}
	if held.Status.Status == 0 {
		if err := s.wallet.setStatus(ctx, held.ID, 1); err != nil {
			return false, err
		}
		run.log("wallet", "Revokes the credential behind the delegation.", detail)
	} else {
		run.log("wallet", "The credential behind the delegation is already revoked.", detail)
	}
	if !held.ExpiresAt.IsZero() && !s.now().Before(held.ExpiresAt) {
		run.log("wallet", "The credential behind the delegation also expired at "+held.ExpiresAt.UTC().Format(time.RFC3339)+".", nil)
	}
	return false, nil
}

func (s *Server) heldCredential(ctx context.Context, uri string, index int) (walletCredential, error) {
	credentials, err := s.wallet.credentials(ctx)
	if err != nil {
		return walletCredential{}, err
	}
	for _, credential := range credentials {
		if credential.Status != nil && credential.Status.URI == uri && credential.Status.Index == index {
			return credential, nil
		}
	}
	return walletCredential{}, errors.New("the wallet does not hold the credential")
}

// ensureValid leaves the wallet with a valid credential of the type. It issues
// one from the template when every credential of the type is revoked. The
// wallet presents its newest valid credential. With revocable set, it also
// issues when that one is protected, because the demo cannot revoke it.
func (s *Server) ensureValid(ctx context.Context, credentialType, template string, revocable bool) (bool, error) {
	credentials, err := s.wallet.credentials(ctx)
	if err != nil {
		return false, err
	}
	now := s.now()
	var newest *walletCredential
	for i, credential := range credentials {
		if credential.Type == credentialType && credential.valid(now) && (newest == nil || credential.IssuedAt.After(newest.IssuedAt)) {
			newest = &credentials[i]
		}
	}
	if newest != nil && !(revocable && newest.Protected) {
		return false, nil
	}
	return true, s.wallet.issue(ctx, template)
}

func (s *Server) act(ctx context.Context, run *Run, mandate *Mandate, selected Case, verifier Verifier) error {
	amount := selected.Task.Amount
	if run.Variant == VariantOverLimit {
		amount = selected.Task.OverLimitAmount
	}
	var shift time.Duration
	if run.Variant == VariantExpired {
		shift = expiredShift
	}
	run.log("agent", fmt.Sprintf("Task: %s Amount: %s %s.", selected.Task.Description, amount, selected.Task.Currency), nil)
	if shift > 0 {
		run.log("agent", fmt.Sprintf("The demo moves the clock of the agent and the verifier %s forward. By then the delegation has expired.", shift), nil)
	}

	business := map[string]any{
		"action":      selected.Action,
		"amount":      amount,
		"currency":    selected.Task.Currency,
		"reference":   selected.Task.Reference,
		"description": selected.Task.Description,
	}
	if shift > 0 {
		business["simulate_expired_mandate"] = true
	}
	run.log("agent", fmt.Sprintf("Sends the request %s to %s.", selected.Action, verifier.Name), business)
	var created struct {
		ID      string `json:"id"`
		Request string `json:"authorization_request"`
	}
	if err := s.call(ctx, http.MethodPost, s.url("/verifier/"+verifier.ID+"/requests"), "application/json", compactJSON(business), &created); err != nil {
		return err
	}

	request, err := parseAuthorizationRequest(created.Request)
	if err != nil {
		return err
	}
	run.log("verifier", "Asks the agent to prove its authority (OpenID4VP request).", request.decoded)
	credentialType, _ := mandate.Report.Credential["vct"].(string)
	if !slices.Contains(request.types, credentialType) {
		return fmt.Errorf("the verifier accepts %s. The delegation is based on %s", strings.Join(request.types, ", "), credentialType)
	}

	token := mandate.Token
	if run.Variant == VariantTampered {
		token, err = raiseLimit(token, "50000.00")
		if err != nil {
			return err
		}
		run.log("agent", "Changes the limit in the delegate payload to 50000.00 after the wallet signed it.", nil)
	}
	token, err = dsdjwt.Present(token, dsdjwt.Presentation{
		Audience: request.clientID,
		Nonce:    request.nonce,
		IssuedAt: s.now().Add(shift),
		AgentKey: mandate.key,
	})
	if err != nil {
		return err
	}
	run.Token = token
	run.log("agent", "Discloses only the audience of this verifier and signs with the agent key "+mandate.AgentKey+".", nil)

	form := url.Values{"vp_token": {compactJSON(map[string][]string{request.queryID: {token}})}, "state": {request.state}}
	run.log("agent", "Sends the delegation to the verifier (dSD-JWT+KB).", nil)
	if err := s.call(ctx, http.MethodPost, request.responseURI, "application/x-www-form-urlencoded", form.Encode(), nil); err != nil {
		return err
	}

	var result verifierResult
	if err := s.call(ctx, http.MethodGet, s.url("/verifier/"+verifier.ID+"/requests/"+created.ID), "", "", &result); err != nil {
		return err
	}
	run.Outcome, run.Reasons, run.Report = result.Status, result.Reasons, result.Report
	if result.Status == "accepted" {
		run.log("verifier", "Accepts the request. All checks passed.", nil)
	} else {
		run.log("verifier", "Refuses the request. "+strings.Join(result.Reasons, " "), nil)
	}
	return nil
}

func (s *Server) call(ctx context.Context, method, target, contentType, body string, into any) error {
	request, err := http.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	if err != nil {
		return err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		var problem struct {
			Description string `json:"error_description"`
		}
		_ = json.NewDecoder(response.Body).Decode(&problem)
		return fmt.Errorf("the verifier returned HTTP %d: %s", response.StatusCode, problem.Description)
	}
	if into == nil {
		return nil
	}
	return json.NewDecoder(response.Body).Decode(into)
}

type authorizationRequest struct {
	clientID, responseURI, nonce, state, queryID string
	types                                        []string
	decoded                                      map[string]any
}

// parseAuthorizationRequest reads a request by value with the client
// identifier prefix redirect_uri (OpenID4VP 1.0 §5.9.3).
func parseAuthorizationRequest(uri string) (*authorizationRequest, error) {
	_, rawQuery, found := strings.Cut(uri, "?")
	if !found {
		return nil, errors.New("the authorization request has no query")
	}
	params, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, fmt.Errorf("authorization request: %w", err)
	}
	request := &authorizationRequest{
		clientID:    params.Get("client_id"),
		responseURI: params.Get("response_uri"),
		nonce:       params.Get("nonce"),
		state:       params.Get("state"),
	}
	if params.Get("response_type") != "vp_token" || params.Get("response_mode") != "direct_post" {
		return nil, errors.New("the agent supports response_type vp_token with response_mode direct_post")
	}
	if request.clientID != "redirect_uri:"+request.responseURI || request.nonce == "" {
		return nil, errors.New("client_id must be redirect_uri: followed by the response_uri, and nonce must be set")
	}
	var query struct {
		Credentials []struct {
			ID     string `json:"id"`
			Format string `json:"format"`
			Meta   struct {
				Types []string `json:"vct_values"`
			} `json:"meta"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal([]byte(params.Get("dcql_query")), &query); err != nil {
		return nil, fmt.Errorf("dcql_query: %w", err)
	}
	if len(query.Credentials) != 1 || query.Credentials[0].Format != "dc+sd-jwt" {
		return nil, errors.New("the agent answers one credential query in the format dc+sd-jwt")
	}
	request.queryID = query.Credentials[0].ID
	request.types = query.Credentials[0].Meta.Types
	var dcql, metadata any
	_ = json.Unmarshal([]byte(params.Get("dcql_query")), &dcql)
	_ = json.Unmarshal([]byte(params.Get("client_metadata")), &metadata)
	request.decoded = map[string]any{
		"response_type":   "vp_token",
		"response_mode":   "direct_post",
		"client_id":       request.clientID,
		"response_uri":    request.responseURI,
		"nonce":           request.nonce,
		"state":           request.state,
		"dcql_query":      dcql,
		"client_metadata": metadata,
	}
	return request, nil
}

// raiseLimit rewrites the delegate payload disclosure with a higher limit.
// The digest in the KB-SD-JWT then matches no disclosure.
func raiseLimit(token, amount string) (string, error) {
	chain, err := dsdjwt.Split(token)
	if err != nil {
		return "", err
	}
	for i, raw := range chain.DelegateDisclosures {
		disclosure, err := dsdjwt.ParseDisclosure(raw)
		if err != nil || disclosure.Name != "" {
			continue
		}
		payload, ok := disclosure.Value.(map[string]any)
		if !ok {
			continue
		}
		mandate, _ := payload["mandate"].(map[string]any)
		limit, _ := mandate["limit"].(map[string]any)
		if limit == nil {
			continue
		}
		limit["amount"] = amount
		chain.DelegateDisclosures[i] = base64.RawURLEncoding.EncodeToString([]byte(compactJSON([]any{disclosure.Salt, payload})))
		return chain.String(), nil
	}
	return "", errors.New("the delegation has no delegate payload disclosure")
}

func checkNames(checks []dsdjwt.Check) []string {
	names := make([]string, 0, len(checks))
	for _, check := range checks {
		names = append(names, check.Name)
	}
	return names
}
