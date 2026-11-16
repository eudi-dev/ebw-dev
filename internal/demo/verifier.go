package demo

import (
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/ebw-dev/internal/dsdjwt"
)

type verifierRequest struct {
	id       string
	verifier Verifier
	action   string
	amount   string
	currency string
	nonce    string
	created  time.Time
	// shift moves the clock of this request. Only the expired mandate demo
	// sets it.
	shift  time.Duration
	result verifierResult
	answerState
}

type verifierResult struct {
	ID string `json:"id"`
	// Status is presentation_required, accepted or refused.
	Status  string         `json:"status"`
	Reasons []string       `json:"reasons"`
	Report  *dsdjwt.Report `json:"report,omitempty"`
}

func (s *Server) verifierClientID(id string) string {
	return "redirect_uri:" + s.url("/verifier/"+id+"/response")
}

// decimalAmount is the form of an amount. big.Rat alone also reads forms such
// as 0x10, 1_000 and .5.
var decimalAmount = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

func parseAmount(text string) (*big.Rat, bool) {
	if !decimalAmount.MatchString(text) {
		return nil, false
	}
	return new(big.Rat).SetString(text)
}

func (s *Server) verifierCreate(w http.ResponseWriter, r *http.Request) {
	verifier, ok := verifiers[r.PathValue("verifier")]
	if !ok {
		writeError(w, http.StatusNotFound, "unknown_verifier", "there is no verifier with this id")
		return
	}
	var body struct {
		Action          string `json:"action"`
		Amount          string `json:"amount"`
		Currency        string `json:"currency"`
		SimulateExpired bool   `json:"simulate_expired_mandate"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if _, valid := parseAmount(body.Amount); !valid || body.Currency == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "amount must be a decimal number and currency must be set")
		return
	}
	if !slices.Contains(verifier.Actions, body.Action) {
		writeError(w, http.StatusBadRequest, "invalid_request", "this verifier only accepts "+strings.Join(verifier.Actions, ", "))
		return
	}
	request := &verifierRequest{
		id: randomID(), verifier: verifier, action: body.Action, amount: body.Amount, currency: body.Currency,
		nonce: randomID(), created: s.now(), answerState: answerState{state: randomID()},
	}
	if body.SimulateExpired {
		request.shift = expiredShift
	}
	request.result = verifierResult{ID: request.id, Status: "presentation_required", Reasons: []string{}}
	s.mu.Lock()
	s.prune(request.created)
	s.requests[request.id] = request
	s.mu.Unlock()

	params := url.Values{
		"response_type":   {"vp_token"},
		"response_mode":   {"direct_post"},
		"client_id":       {s.verifierClientID(verifier.ID)},
		"response_uri":    {s.url("/verifier/" + verifier.ID + "/response")},
		"nonce":           {request.nonce},
		"state":           {request.state},
		"dcql_query":      {compactJSON(map[string]any{"credentials": []any{credentialQuery(credentialQueryID, verifier.CredentialTypes, verifier.Claims)}})},
		"client_metadata": {compactJSON(clientMetadata)},
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"id":                    request.id,
		"status":                request.result.Status,
		"authorization_request": "openid4vp://?" + encodeQuery(params),
	})
}

func (s *Server) verifierResponse(w http.ResponseWriter, r *http.Request) {
	if !readWalletResponse(w, r) {
		return
	}
	request, ok := claimAnswer(s, s.requests, r.PostFormValue("state"), func(candidate *verifierRequest) bool {
		return candidate.verifier.ID == r.PathValue("verifier") && candidate.result.Status == "presentation_required"
	})
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", "no open request matches this state")
		return
	}
	result := s.decide(r, request)
	s.mu.Lock()
	request.result, request.checking = result, false
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{})
}

func (s *Server) verifierResult(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	request, ok := s.requests[r.PathValue("id")]
	var result verifierResult
	if ok && request.verifier.ID == r.PathValue("verifier") {
		result = request.result
	} else {
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "unknown_request", "there is no request with this id")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// decide runs "Verifier checks" 1 to 6 of docs/chain-format.md.
func (s *Server) decide(r *http.Request, request *verifierRequest) verifierResult {
	result := verifierResult{ID: request.id, Status: "refused", Reasons: []string{}}
	token, err := vpToken(r, credentialQueryID)
	if err != nil {
		result.Reasons = append(result.Reasons, sentence(err.Error()))
		return result
	}
	if err := s.ensureTrust(r.Context()); err != nil {
		result.Reasons = append(result.Reasons, sentence(err.Error()))
		return result
	}
	// The trusted lists and the status list are live data of the wallet.
	// Their checks keep the real time. Only the chain sees the shifted clock.
	live := s.now()
	now := live.Add(request.shift)
	clientID := s.verifierClientID(request.verifier.ID)
	report, err := dsdjwt.VerifyPresentation(token,
		dsdjwt.PresentationExpectation{Audience: clientID, Nonce: request.nonce},
		dsdjwt.Options{
			Now:           now,
			ResolveIssuer: s.trust.ResolveIssuer(request.verifier.TrustedLists, live),
			CheckStatus:   s.trust.CheckStatus(r.Context(), request.verifier.TrustedLists, live),
		})
	result.Report = report
	if errors.Is(err, dsdjwt.ErrNoDelegation) {
		result.Reasons = append(result.Reasons, "The presentation carries no delegation chain.")
		return result
	}
	if err != nil {
		result.Reasons = append(result.Reasons, sentence(err.Error()))
		return result
	}
	applyPolicy(report, request, clientID)
	for _, check := range report.FailedChecks() {
		result.Reasons = append(result.Reasons, sentence(check.Detail))
	}
	if report.Valid {
		result.Status = "accepted"
	}
	return result
}

// applyPolicy adds the checks of step 6 to the report.
func applyPolicy(report *dsdjwt.Report, request *verifierRequest, clientID string) {
	defer report.Seal()
	if link := report.Link(dsdjwt.LinkCredential); report.Credential != nil {
		vct, _ := report.Credential["vct"].(string)
		var err error
		if !slices.Contains(request.verifier.CredentialTypes, vct) {
			err = fmt.Errorf("this verifier does not accept the credential type %s", vct)
		}
		link.Add(dsdjwt.CheckPolicyType, err, vct)
	}
	mandate := report.Mandate
	if mandate == nil {
		return
	}
	link := report.Link(dsdjwt.LinkMandate)

	var actionErr error
	if !slices.Contains(mandate.Actions, request.action) {
		actionErr = fmt.Errorf("the delegation allows %s. The request is %s", strings.Join(mandate.Actions, ", "), request.action)
	}
	link.Add(dsdjwt.CheckPolicyAction, actionErr, request.action)

	link.Add(dsdjwt.CheckPolicyLimit, withinLimit(request, mandate.Limit),
		fmt.Sprintf("%s %s is within %s %s", request.amount, request.currency, mandate.Limit.Amount, mandate.Limit.Currency))

	var audienceErr error
	if !slices.Contains(mandate.Audiences, clientID) {
		audienceErr = errors.New("the delegation does not list this verifier")
	}
	link.Add(dsdjwt.CheckPolicyAudience, audienceErr, clientID)
}

func withinLimit(request *verifierRequest, limit dsdjwt.Limit) error {
	amount, _ := parseAmount(request.amount)
	highest, ok := parseAmount(limit.Amount)
	if !ok {
		return errors.New("the delegation has no usable limit")
	}
	if request.currency != limit.Currency {
		return fmt.Errorf("the request is in %s and the limit is in %s", request.currency, limit.Currency)
	}
	if amount.Cmp(highest) > 0 {
		return fmt.Errorf("%s %s is above the limit of %s %s", request.amount, request.currency, limit.Amount, limit.Currency)
	}
	return nil
}

func sentence(text string) string {
	if text == "" {
		return ""
	}
	text = strings.ToUpper(text[:1]) + text[1:]
	if !strings.HasSuffix(text, ".") {
		text += "."
	}
	return text
}

var checkLabels = map[string]string{
	dsdjwt.CheckStructure:        "Structure of the token",
	dsdjwt.CheckIssuerSignature:  "Issuer signature",
	dsdjwt.CheckIssuerTrusted:    "Issuer on a trusted list",
	dsdjwt.CheckDisclosures:      "Disclosures of the credential",
	dsdjwt.CheckCredentialValid:  "Validity of the credential",
	dsdjwt.CheckStatus:           "Not revoked (status list)",
	dsdjwt.CheckHolderKey:        "Holder key in the credential",
	dsdjwt.CheckMandateType:      "Type of the delegation token (typ)",
	dsdjwt.CheckHolderSignature:  "Signature with the holder key",
	dsdjwt.CheckMandateHash:      "Delegation linked to the credential (sd_hash)",
	dsdjwt.CheckMandateTime:      "Validity of the delegation token",
	dsdjwt.CheckOnePayload:       "Exactly one disclosed delegate payload",
	dsdjwt.CheckDelegateContent:  "Disclosures of the delegation",
	dsdjwt.CheckMandateValid:     "Validity of the delegation",
	dsdjwt.CheckAgentKey:         "Agent key in the delegation",
	dsdjwt.CheckPresentationType: "Type of the presentation token (typ)",
	dsdjwt.CheckAgentSignature:   "Signature with the agent key",
	dsdjwt.CheckAudience:         "Audience",
	dsdjwt.CheckNonce:            "Nonce",
	dsdjwt.CheckIssuedAt:         "Issue time of the presentation",
	dsdjwt.CheckPresentationHash: "Presentation linked to the delegation (sd_hash)",
	dsdjwt.CheckTransactionData:  "Hash of the transaction data",
	dsdjwt.CheckRequestedPayload: "Delegation matches the request",
	dsdjwt.CheckPolicyType:       "Accepted credential type",
	dsdjwt.CheckPolicyAction:     "Action covered by the delegation",
	dsdjwt.CheckPolicyLimit:      "Amount within the limit",
	dsdjwt.CheckPolicyAudience:   "Delegation lists this verifier",
	dsdjwt.CheckKeyBindingSDHash: "Presentation linked to the credential (sd_hash)",
	CheckPolicyScope:             "Power covers this registration",
	CheckPolicyValidity:          "Power valid on the date of the registration",
	CheckPolicyIdentifier:        "Same company identifier in both credentials",
	CheckPolicyName:              "Same company name in both credentials",
}
