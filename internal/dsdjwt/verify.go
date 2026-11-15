package dsdjwt

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt/delegate"
)

const (
	Pass    = "pass"
	Fail    = "fail"
	Skipped = "skipped"
)

const (
	LinkCredential   = "credential"
	LinkMandate      = "mandate"
	LinkPresentation = "presentation"
)

// Names of the checks. The numbers refer to "Verifier checks" in
// docs/chain-format.md.
const (
	CheckStructure        = "structure"           // 1
	CheckIssuerSignature  = "issuer_signature"    // 2
	CheckIssuerTrusted    = "issuer_trusted"      // 2
	CheckDisclosures      = "disclosures"         // 2
	CheckCredentialValid  = "credential_validity" //nolint:gosec // check name
	CheckStatus           = "status"              // 2
	CheckHolderKey        = "holder_key"          // 2
	CheckMandateType      = "kb_sd_jwt_typ"       // 3
	CheckHolderSignature  = "holder_signature"    // 3
	CheckMandateHash      = "kb_sd_jwt_sd_hash"   // 3
	CheckMandateTime      = "kb_sd_jwt_validity"  // 3
	CheckOnePayload       = "one_delegate_payload"
	CheckDelegateContent  = "delegate_disclosures"
	CheckMandateValid     = "mandate_validity"       // 4
	CheckAgentKey         = "agent_key"              // 4
	CheckPresentationType = "kb_jwt_typ"             // 5
	CheckAgentSignature   = "agent_signature"        // 5
	CheckAudience         = "audience"               // 5
	CheckNonce            = "nonce"                  // 5
	CheckIssuedAt         = "issued_at"              // 5
	CheckPresentationHash = "kb_jwt_sd_hash"         // 5
	CheckTransactionData  = "transaction_data_hash"  // mandate receipt
	CheckRequestedPayload = "requested_payload"      // mandate receipt
	CheckPolicyType       = "policy_credential_type" // 6, added by the verifier
	CheckPolicyAction     = "policy_action"          // 6
	CheckPolicyLimit      = "policy_limit"           // 6
	CheckPolicyAudience   = "policy_audience"        // 6
)

type Check struct {
	Name   string `json:"name"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
}

type Link struct {
	Kind   string `json:"kind"`
	Signer string `json:"signer"`
	// KeyThumbprint is the RFC 7638 thumbprint of the signing key.
	KeyThumbprint string         `json:"key_thumbprint,omitempty"`
	Header        map[string]any `json:"header,omitempty"`
	Claims        map[string]any `json:"claims,omitempty"`
	Checks        []Check        `json:"checks"`
}

// Add records a check on the link. A nil error is a pass.
func (l *Link) Add(name string, err error, passDetail string) bool {
	if err != nil {
		l.Checks = append(l.Checks, Check{Name: name, Result: Fail, Detail: err.Error()})
		return false
	}
	l.Checks = append(l.Checks, Check{Name: name, Result: Pass, Detail: passDetail})
	return true
}

func (l *Link) skip(detail string, names ...string) {
	for _, name := range names {
		l.Checks = append(l.Checks, Check{Name: name, Result: Skipped, Detail: detail})
	}
}

type Report struct {
	Valid      bool           `json:"valid"`
	Structure  Check          `json:"structure"`
	Links      []*Link        `json:"links"`
	Credential map[string]any `json:"credential,omitempty"`
	Mandate    *Mandate       `json:"mandate,omitempty"`
}

func (r *Report) Link(kind string) *Link {
	for _, link := range r.Links {
		if link.Kind == kind {
			return link
		}
	}
	return nil
}

func (r *Report) FailedChecks() []Check {
	var failed []Check
	if r.Structure.Result == Fail {
		failed = append(failed, r.Structure)
	}
	for _, link := range r.Links {
		for _, check := range link.Checks {
			if check.Result == Fail {
				failed = append(failed, check)
			}
		}
	}
	return failed
}

// Seal sets Valid from the checks. Call it again after adding policy checks.
func (r *Report) Seal() {
	r.Valid = len(r.FailedChecks()) == 0
}

type Issuer struct {
	Name string
	Key  *ecdsa.PublicKey
	// TrustError says why the key is not trusted. Nil means trusted.
	TrustError error
}

var ErrNoStatus = errors.New("the credential has no status list entry")

const (
	clockSkew = time.Minute
	// maxPresentationAge bounds the age of a Key Binding JWT.
	maxPresentationAge = 5 * time.Minute
)

type Options struct {
	Now           time.Time
	ResolveIssuer func(header, claims map[string]any) (Issuer, error)
	// CheckStatus looks up the status list entry in the signed payload of the
	// credential. It returns ErrNoStatus for a credential without an entry.
	// Nil skips the check.
	CheckStatus func(claims map[string]any) error
}

type MandateExpectation struct {
	Audience string
	Nonce    string
	Sent     TransactionData
}

type PresentationExpectation struct {
	Audience string
	Nonce    string
}

// VerifyMandate checks a dSD-JWT that a wallet returned for a mandate request.
// A token without delegation gives ErrNoDelegation.
func VerifyMandate(token string, expected MandateExpectation, opts Options) (*Report, error) {
	chain, report, err := start(token)
	if err != nil {
		return report, err
	}
	if chain.DelegateKBJWT != "" {
		report.Structure = Check{Name: CheckStructure, Result: Fail, Detail: "A delegation must end with ~. This token has a delegate Key Binding JWT."}
		return report, nil
	}
	state := verifyChain(chain, report, opts)
	link := report.Link(LinkMandate)
	if state.kbSD == nil {
		link.skip("the KB-SD-JWT does not parse", CheckAudience, CheckNonce, CheckTransactionData)
	} else {
		link.Add(CheckAudience, equalClaim(state.kbSD.Payload, "aud", expected.Audience), "")
		link.Add(CheckNonce, equalClaim(state.kbSD.Payload, "nonce", expected.Nonce), "")
		link.Add(CheckTransactionData, transactionDataHash(state.kbSD.Payload, expected.Sent.Encoded), "")
	}
	switch {
	case state.payloadDisclosure == "":
		link.skip("no delegate payload is disclosed", CheckRequestedPayload)
	case state.payloadDisclosure != expected.Sent.PayloadDisclosure:
		link.Add(CheckRequestedPayload, errors.New("the signed delegate payload differs from the one in the request"), "")
	default:
		link.Add(CheckRequestedPayload, nil, "")
	}
	report.Seal()
	return report, nil
}

// VerifyPresentation checks a dSD-JWT+KB that an agent presented. It runs
// steps 1 to 5 of "Verifier checks" in docs/chain-format.md.
func VerifyPresentation(token string, expected PresentationExpectation, opts Options) (*Report, error) {
	chain, report, err := start(token)
	if err != nil {
		return report, err
	}
	if chain.DelegateKBJWT == "" {
		report.Structure = Check{Name: CheckStructure, Result: Fail, Detail: "the token ends with ~ and has no delegate KB-JWT"}
		return report, nil
	}
	state := verifyChain(chain, report, opts)

	link := &Link{Kind: LinkPresentation, Signer: "Agent"}
	report.Links = append(report.Links, link)
	defer report.Seal()
	kb, err := parseJWT(chain.DelegateKBJWT)
	if err != nil {
		link.Add(CheckPresentationType, fmt.Errorf("the delegate KB-JWT does not parse: %w", err), "")
		link.skip("the delegate KB-JWT does not parse", CheckAgentSignature, CheckAudience, CheckNonce, CheckIssuedAt, CheckPresentationHash)
		return report, nil
	}
	link.Header, link.Claims = kb.Header, kb.Payload
	link.Add(CheckPresentationType, equalClaim(kb.Header, "typ", "kb+jwt"), "")
	if state.agentKey == nil {
		link.skip("the agent key is unknown", CheckAgentSignature)
	} else {
		if report.Mandate != nil {
			link.Signer = report.Mandate.Agent.Name
		}
		link.KeyThumbprint = state.agentThumbprint
		link.Add(CheckAgentSignature, VerifyES256(chain.DelegateKBJWT, kb.Header, state.agentKey), "signed with cnf of the delegate payload")
	}
	keyBinding(link, kb.Payload, expected.Audience, expected.Nonce, opts)
	link.Add(CheckPresentationHash, equalClaim(kb.Payload, "sd_hash", hashASCII(chain.delegatePart())), "")
	return report, nil
}

func start(token string) (*Chain, *Report, error) {
	report := &Report{Structure: Check{Name: CheckStructure, Result: Pass}}
	chain, err := Split(token)
	if err != nil {
		report.Structure = Check{Name: CheckStructure, Result: Fail, Detail: err.Error()}
		if errors.Is(err, ErrNoDelegation) {
			return nil, report, err
		}
		return nil, report, fmt.Errorf("splitting the token: %w", err)
	}
	return chain, report, nil
}

type chainState struct {
	kbSD              *jwt
	payloadDisclosure string
	agentKey          *ecdsa.PublicKey
	agentThumbprint   string
}

// verifyChain runs steps 2 to 4 and fills the first 2 links of the report.
func verifyChain(chain *Chain, report *Report, opts Options) chainState {
	var state chainState
	defer report.Seal()

	credential := &Link{Kind: LinkCredential, Signer: "Issuer"}
	mandate := &Link{Kind: LinkMandate, Signer: "Holder"}
	report.Links = append(report.Links, credential, mandate)

	holderKey := verifyCredential(chain, credential, report, opts)

	kbSD, err := parseJWT(chain.KBSDJWT)
	if err != nil {
		mandate.Add(CheckMandateType, fmt.Errorf("the KB-SD-JWT does not parse: %w", err), "")
		mandate.skip("the KB-SD-JWT does not parse", CheckHolderSignature, CheckMandateHash, CheckMandateTime,
			CheckOnePayload, CheckDelegateContent, CheckMandateValid, CheckAgentKey)
		return state
	}
	state.kbSD = kbSD
	mandate.Header, mandate.Claims = kbSD.Header, kbSD.Payload
	mandate.Add(CheckMandateType, equalClaim(kbSD.Header, "typ", "kb-sd-jwt+kb"), "")
	if holderKey == nil {
		mandate.skip("the holder key is unknown", CheckHolderSignature)
	} else {
		mandate.KeyThumbprint = holderKey.thumbprint
		mandate.Add(CheckHolderSignature, VerifyES256(chain.KBSDJWT, kbSD.Header, holderKey.key), "signed with cnf of the credential")
	}
	mandate.Add(CheckMandateHash, equalClaim(kbSD.Payload, "sd_hash", hashASCII(chain.sdJWTPart())), "")
	mandate.Add(CheckMandateTime, firstError(issuedAt(kbSD.Payload, opts, 0), func() error { return validity(kbSD.Payload, opts) }), "")

	payloadDisclosure, err := delegatePayload(chain, kbSD.Payload)
	if !mandate.Add(CheckOnePayload, err, "") {
		mandate.skip("no delegate payload is disclosed", CheckDelegateContent, CheckMandateValid, CheckAgentKey)
		return state
	}
	state.payloadDisclosure = payloadDisclosure.Raw
	// The holder signs the digest of the delegate payload disclosure. Its
	// claims count even when another delegate disclosure is broken.
	signed, _ := payloadDisclosure.Value.(map[string]any)
	claims, err := resolveDelegate(chain.delegatePart())
	var shapeErr error
	if mandate.Add(CheckDelegateContent, err, "") {
		mandate.Claims = map[string]any{"kb_sd_jwt": kbSD.Payload, "delegate_payload": claims}
		report.Mandate, shapeErr = mandateFromClaims(claims)
	}
	mandate.Add(CheckMandateValid, firstError(shapeErr, func() error { return delegateValidity(signed, opts) }), "")
	agentJWK, agentKey, err := jwkFromClaims(signed)
	if mandate.Add(CheckAgentKey, err, "") {
		state.agentKey, state.agentThumbprint = agentKey, agentJWK.Thumbprint()
	}
	return state
}

func firstError(err error, next func() error) error {
	if err != nil {
		return err
	}
	return next()
}

type holderKey struct {
	key        *ecdsa.PublicKey
	thumbprint string
}

// neverDisclosed are the claims that draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3
// keeps out of Disclosures, sub-claims included.
var neverDisclosed = []string{"iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "aka_vcts", "status"}

// verifyCredential runs step 2 and returns the holder key. Validity, status
// and cnf come from the signed payload, so a broken or withheld disclosure
// cannot change them.
func verifyCredential(chain *Chain, link *Link, report *Report, opts Options) *holderKey {
	issuerJWT, err := parseJWT(chain.IssuerJWT)
	if err != nil {
		link.Add(CheckIssuerSignature, fmt.Errorf("the Issuer-signed JWT does not parse: %w", err), "")
		link.skip("the Issuer-signed JWT does not parse", CheckIssuerTrusted, CheckDisclosures, CheckCredentialValid, CheckStatus, CheckHolderKey)
		return nil
	}
	link.Header = issuerJWT.Header
	signed := issuerJWT.Payload
	issuer, err := opts.ResolveIssuer(issuerJWT.Header, signed)
	if err != nil {
		link.Add(CheckIssuerSignature, fmt.Errorf("no issuer key: %w", err), "")
		link.skip("the issuer key is unknown", CheckIssuerTrusted)
	} else {
		link.Signer = issuer.Name
		if jwk, err := PublicJWK(issuer.Key); err == nil {
			link.KeyThumbprint = jwk.Thumbprint()
		}
		link.Add(CheckIssuerSignature, firstError(equalClaim(issuerJWT.Header, "typ", "dc+sd-jwt"), func() error { return VerifyES256(chain.IssuerJWT, issuerJWT.Header, issuer.Key) }), "")
		link.Add(CheckIssuerTrusted, issuer.TrustError, "")
	}

	credential, err := processed(chain.sdJWTPart())
	if err == nil {
		err = protocolClaimsSigned(signed, credential.ResolvedClaims)
	}
	if link.Add(CheckDisclosures, err, fmt.Sprintf("%d disclosures", len(chain.Disclosures))) {
		link.Claims = credential.ResolvedClaims
		report.Credential = credential.ResolvedClaims
	}
	link.Add(CheckCredentialValid, credentialValidity(signed, opts), "")

	switch {
	case opts.CheckStatus == nil:
		link.skip("this verifier does not check the status", CheckStatus)
	case link.Check(CheckIssuerSignature) != Pass:
		link.skip("the issuer signature is not valid", CheckStatus)
	case link.Check(CheckIssuerTrusted) != Pass:
		link.skip("the issuer is not trusted", CheckStatus)
	default:
		err := opts.CheckStatus(signed)
		if errors.Is(err, ErrNoStatus) {
			link.skip(err.Error(), CheckStatus)
		} else {
			link.Add(CheckStatus, err, "")
		}
	}

	holderJWK, key, err := jwkFromClaims(signed)
	if !link.Add(CheckHolderKey, err, holderJWK.Thumbprint()) {
		return nil
	}
	return &holderKey{key: key, thumbprint: holderJWK.Thumbprint()}
}

// protocolClaimsSigned refuses a protocol claim that a disclosure adds or
// changes. Processing removes every digest, so a claim with a digest inside
// differs from its signed form even when the holder withholds the disclosure.
func protocolClaimsSigned(signed, resolved map[string]any) error {
	for _, name := range neverDisclosed {
		if !reflect.DeepEqual(signed[name], resolved[name]) {
			return fmt.Errorf("%s is selectively disclosable, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids", name)
		}
	}
	return nil
}

func (l *Link) Check(name string) string {
	for _, check := range l.Checks {
		if check.Name == name {
			return check.Result
		}
	}
	return ""
}

// delegatePayload returns the disclosure of the single disclosed element of
// delegate_payload (draft-ietf-oauth-delegate-sd-jwt-00 §6).
func delegatePayload(chain *Chain, kbSD map[string]any) (Disclosure, error) {
	entries, ok := kbSD["delegate_payload"].([]any)
	if !ok || len(entries) == 0 {
		return Disclosure{}, errors.New("the KB-SD-JWT has no delegate_payload array")
	}
	digests := map[string]bool{}
	for _, entry := range entries {
		digest, placeholder := arrayDigest(entry)
		text, isText := digest.(string)
		if !placeholder || !isText {
			return Disclosure{}, errors.New("an element of delegate_payload is not a digest")
		}
		if digests[text] {
			return Disclosure{}, errors.New("a digest appears twice in delegate_payload")
		}
		digests[text] = true
	}
	var found []Disclosure
	for _, raw := range chain.DelegateDisclosures {
		disclosure, err := ParseDisclosure(raw)
		if err != nil {
			return Disclosure{}, err
		}
		if digests[disclosure.Digest] {
			found = append(found, disclosure)
		}
	}
	if len(found) != 1 {
		return Disclosure{}, fmt.Errorf("%d elements of delegate_payload are disclosed. Only one is allowed", len(found))
	}
	if _, isObject := found[0].Value.(map[string]any); found[0].isClaim || !isObject {
		return Disclosure{}, errors.New("the delegate payload disclosure is not [salt, object]")
	}
	return found[0], nil
}

// resolveDelegate runs after delegatePayload found exactly one disclosed
// object, so the payload is never nil.
func resolveDelegate(delegatePart string) (map[string]any, error) {
	kbSD, err := processed(delegatePart)
	if err != nil {
		return nil, err
	}
	return delegate.NewLink(kbSD).Payload, nil
}

func equalClaim(claims map[string]any, name, want string) error {
	got, ok := claims[name].(string)
	if !ok {
		return fmt.Errorf("%s is missing", name)
	}
	if got != want {
		return fmt.Errorf("%s is %q, expected %q", name, got, want)
	}
	return nil
}

// maxNumericDate is 9999-12-31T23:59:59Z. time.Time formats no later year.
const maxNumericDate = 253402300799

// numericDate reads a time claim. RFC 7519 §2 makes a NumericDate a JSON
// number of seconds since the epoch.
func numericDate(claims map[string]any, name string) (time.Time, bool, error) {
	value, present := claims[name]
	if !present {
		return time.Time{}, false, nil
	}
	seconds, ok := value.(float64)
	if !ok || math.IsNaN(seconds) || seconds < 0 || seconds > maxNumericDate {
		return time.Time{}, true, fmt.Errorf("%s is not a NumericDate", name)
	}
	return time.Unix(int64(seconds), 0).UTC(), true, nil
}

func validity(claims map[string]any, opts Options) error {
	exp, ok, err := numericDate(claims, "exp")
	if err != nil {
		return err
	}
	if ok && !opts.Now.Before(exp) {
		return fmt.Errorf("expired at %s", exp.Format(time.RFC3339))
	}
	nbf, ok, err := numericDate(claims, "nbf")
	if err != nil {
		return err
	}
	if ok && opts.Now.Add(clockSkew).Before(nbf) {
		return fmt.Errorf("not valid before %s", nbf.Format(time.RFC3339))
	}
	iat, ok, err := numericDate(claims, "iat")
	if err != nil {
		return err
	}
	if ok && opts.Now.Add(clockSkew).Before(iat) {
		return fmt.Errorf("issued in the future at %s", iat.Format(time.RFC3339))
	}
	return nil
}

// delegateValidity requires exp. A short exp is the only way to end a
// delegation (draft-ietf-oauth-delegate-sd-jwt-00 §8.3).
func delegateValidity(claims map[string]any, opts Options) error {
	if _, present := claims["exp"]; !present {
		return errors.New("the delegate payload has no exp")
	}
	return validity(claims, opts)
}

// credentialValidity requires exp in the signed payload. A verifier cannot
// see an exp that the issuer put into _sd and the holder withheld.
func credentialValidity(signed map[string]any, opts Options) error {
	if _, present := signed["exp"]; !present {
		return errors.New("the Issuer-signed JWT has no exp")
	}
	return validity(signed, opts)
}

// keyBinding checks aud, nonce and iat of a Key Binding JWT (RFC 9901 §7.3).
func keyBinding(link *Link, claims map[string]any, audience, nonce string, opts Options) {
	link.Add(CheckAudience, equalClaim(claims, "aud", audience), "")
	link.Add(CheckNonce, equalClaim(claims, "nonce", nonce), "")
	link.Add(CheckIssuedAt, issuedAt(claims, opts, maxPresentationAge), "")
}

func issuedAt(claims map[string]any, opts Options, maxAge time.Duration) error {
	iat, ok, err := numericDate(claims, "iat")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("iat is missing")
	}
	if opts.Now.Add(clockSkew).Before(iat) {
		return fmt.Errorf("issued in the future at %s", iat.Format(time.RFC3339))
	}
	if maxAge > 0 && opts.Now.Sub(iat) > maxAge+clockSkew {
		return fmt.Errorf("the iat %s is more than %s ago", iat.Format(time.RFC3339), maxAge)
	}
	return nil
}

// transactionDataHash checks `transaction_data_hashes` against the sent entry
// (OpenID4VP 1.0 Appendix B.3.3.1).
func transactionDataHash(kbSD map[string]any, sent string) error {
	if alg, present := kbSD["transaction_data_hashes_alg"]; present && alg != "sha-256" {
		return fmt.Errorf("unsupported transaction_data_hashes_alg %v", alg)
	}
	hashes, _ := kbSD["transaction_data_hashes"].([]any)
	if len(hashes) != 1 || hashes[0] != hashASCII(sent) {
		return errors.New("transaction_data_hashes does not hold the hash of the sent entry")
	}
	return nil
}
