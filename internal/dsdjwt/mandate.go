package dsdjwt

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"time"
)

// MandateType is the vct of the delegate payload (docs/chain-format.md).
const MandateType = "urn:eudi-test:business:agent-mandate:1"

type Agent struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Operator string `json:"operator"`
}

// Limit is the highest amount of one action. Amount is a decimal string.
type Limit struct {
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
}

type Mandate struct {
	Type      string    `json:"vct"`
	IssuedAt  time.Time `json:"issued_at"`
	Expires   time.Time `json:"expires"`
	AgentKey  JWK       `json:"agent_key"`
	Agent     Agent     `json:"agent"`
	Purpose   string    `json:"purpose"`
	Actions   []string  `json:"actions"`
	Limit     Limit     `json:"limit"`
	Audiences []string  `json:"audiences"`
}

// TransactionData is a `delegate` transaction data entry
// (draft-ietf-oauth-delegate-sd-jwt-00 §7.1) with its parts.
type TransactionData struct {
	Encoded           string
	PayloadDisclosure string
	Disclosures       []string
	// Decoded is the entry with each disclosure as its JSON array, for display.
	Decoded map[string]any
}

// NewTransactionData builds the delegate payload of a mandate and wraps it in
// a transaction data entry. Every audience becomes its own disclosure.
func NewTransactionData(mandate Mandate, credentialIDs []string) (TransactionData, error) {
	audiences := make([]any, 0, len(mandate.Audiences))
	disclosures := make([]string, 0, len(mandate.Audiences))
	decoded := make([]any, 0, len(mandate.Audiences))
	for _, audience := range mandate.Audiences {
		disclosure, err := NewDisclosure(audience)
		if err != nil {
			return TransactionData{}, err
		}
		audiences = append(audiences, map[string]any{"...": disclosure.Digest})
		disclosures = append(disclosures, disclosure.Raw)
		decoded = append(decoded, []any{disclosure.Salt, disclosure.Value})
	}
	payload := map[string]any{
		"vct":   MandateType,
		"iat":   mandate.IssuedAt.Unix(),
		"exp":   mandate.Expires.Unix(),
		"cnf":   map[string]any{"jwk": mandate.AgentKey},
		"agent": mandate.Agent,
		"mandate": map[string]any{
			"purpose":   mandate.Purpose,
			"actions":   mandate.Actions,
			"limit":     mandate.Limit,
			"audiences": audiences,
		},
	}
	payloadDisclosure, err := NewDisclosure(payload)
	if err != nil {
		return TransactionData{}, err
	}
	entry := map[string]any{
		"type":                        "delegate",
		"credential_ids":              credentialIDs,
		"format":                      "dSD-JWT+KB",
		"delegate_payload_disclosure": payloadDisclosure.Raw,
		"delegate_disclosures":        disclosures,
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return TransactionData{}, err
	}
	display := maps.Clone(entry)
	display["delegate_payload_disclosure"] = []any{payloadDisclosure.Salt, payloadDisclosure.Value}
	display["delegate_disclosures"] = decoded
	return TransactionData{
		Encoded:           b64.EncodeToString(encoded),
		PayloadDisclosure: payloadDisclosure.Raw,
		Disclosures:       disclosures,
		Decoded:           display,
	}, nil
}

func mandateFromClaims(claims map[string]any) (*Mandate, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	var wire struct {
		Type    string `json:"vct"`
		Iat     int64  `json:"iat"`
		Exp     int64  `json:"exp"`
		Agent   Agent  `json:"agent"`
		Mandate struct {
			Purpose   string   `json:"purpose"`
			Actions   []string `json:"actions"`
			Limit     Limit    `json:"limit"`
			Audiences []string `json:"audiences"`
		} `json:"mandate"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("the delegate payload does not have the mandate shape: %w", err)
	}
	if wire.Type != MandateType {
		return nil, fmt.Errorf("the delegate payload has the type %q", wire.Type)
	}
	mandate := &Mandate{
		Type:      wire.Type,
		IssuedAt:  time.Unix(wire.Iat, 0).UTC(),
		Expires:   time.Unix(wire.Exp, 0).UTC(),
		Agent:     wire.Agent,
		Purpose:   wire.Mandate.Purpose,
		Actions:   wire.Mandate.Actions,
		Limit:     wire.Mandate.Limit,
		Audiences: wire.Mandate.Audiences,
	}
	if key, _, err := jwkFromClaims(claims); err == nil {
		mandate.AgentKey = key
	}
	return mandate, nil
}

type Presentation struct {
	Audience string
	Nonce    string
	IssuedAt time.Time
	AgentKey *ecdsa.PrivateKey
}

// Present turns a dSD-JWT into a dSD-JWT+KB for one verifier. It drops the
// audience disclosures of other verifiers and appends the delegate KB-JWT.
func Present(mandateToken string, presentation Presentation) (string, error) {
	chain, err := Split(mandateToken)
	if err != nil {
		return "", err
	}
	if chain.DelegateKBJWT != "" {
		return "", errors.New("the token already ends with a delegate KB-JWT")
	}
	kept := make([]string, 0, len(chain.DelegateDisclosures))
	for _, raw := range chain.DelegateDisclosures {
		disclosure, err := ParseDisclosure(raw)
		if err != nil {
			return "", err
		}
		// Every delegate disclosure of a string is an audience in this
		// format. The delegate payload disclosure holds an object.
		if audience, isText := disclosure.Value.(string); isText && !disclosure.isClaim && audience != presentation.Audience {
			continue
		}
		kept = append(kept, raw)
	}
	chain.DelegateDisclosures = kept
	kbJWT, err := SignES256(presentation.AgentKey,
		map[string]any{"typ": "kb+jwt", "alg": "ES256"},
		map[string]any{
			"iat":     presentation.IssuedAt.Unix(),
			"aud":     presentation.Audience,
			"nonce":   presentation.Nonce,
			"sd_hash": hashASCII(chain.delegatePart()),
		})
	if err != nil {
		return "", err
	}
	chain.DelegateKBJWT = kbJWT
	return chain.String(), nil
}
