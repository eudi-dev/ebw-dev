package dsdjwt

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt"
)

// Disclosure is a decoded disclosure (RFC 9901 §4.2).
type Disclosure struct {
	Raw    string
	Digest string
	Salt   string
	// Name is empty for an array element and for a delegate payload.
	Name    string
	Value   any
	isClaim bool
}

func ParseDisclosure(raw string) (Disclosure, error) {
	data, err := b64.DecodeString(raw)
	if err != nil {
		return Disclosure{}, fmt.Errorf("disclosure is not base64url: %w", err)
	}
	var parts []any
	if err := json.Unmarshal(data, &parts); err != nil {
		return Disclosure{}, fmt.Errorf("disclosure is not a JSON array: %w", err)
	}
	disclosure := Disclosure{Raw: raw, Digest: hashASCII(raw)}
	if len(parts) != 2 && len(parts) != 3 {
		return Disclosure{}, fmt.Errorf("a disclosure must have 2 or 3 elements. This one has %d", len(parts))
	}
	salt, ok := parts[0].(string)
	if !ok {
		return Disclosure{}, errors.New("the salt of a disclosure is not a string")
	}
	disclosure.Salt = salt
	disclosure.Value = parts[len(parts)-1]
	if len(parts) == 3 {
		name, ok := parts[1].(string)
		if !ok {
			return Disclosure{}, errors.New("the claim name of a disclosure is not a string")
		}
		disclosure.Name = name
		disclosure.isClaim = true
	}
	return disclosure, nil
}

// NewDisclosure returns a disclosure of 2 elements with a fresh salt. Array
// elements and delegate payloads use this form.
func NewDisclosure(value any) (Disclosure, error) {
	return encodeDisclosure(randomSalt(), value)
}

func NewClaimDisclosure(name string, value any) (Disclosure, error) {
	return encodeDisclosure(randomSalt(), name, value)
}

func encodeDisclosure(parts ...any) (Disclosure, error) {
	data, err := json.Marshal(parts)
	if err != nil {
		return Disclosure{}, err
	}
	return ParseDisclosure(b64.EncodeToString(data))
}

func randomSalt() string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	return b64.EncodeToString(salt)
}

func arrayDigest(element any) (any, bool) {
	object, ok := element.(map[string]any)
	if !ok || len(object) != 1 {
		return nil, false
	}
	digest, ok := object["..."]
	return digest, ok
}

// processed parses an SD-JWT and returns its Processed SD-JWT Payload (RFC 9901
// §7.1). The demo accepts only sha-256, and sdjwt.ParseLenient also reads
// sha-384 and sha-512.
func processed(sdJWT string) (*sdjwt.Token, error) {
	token, err := sdjwt.ParseLenient(sdJWT)
	if err != nil {
		return nil, err
	}
	if alg, present := token.Payload["_sd_alg"]; present && alg != "sha-256" {
		return nil, fmt.Errorf("unsupported _sd_alg %v", alg)
	}
	if len(token.Deviations) > 0 {
		return nil, errors.New(strings.Join(token.Deviations, ". "))
	}
	return token, nil
}

type jwt struct {
	Header  map[string]any
	Payload map[string]any
}

// parseJWT decodes the header and the payload of a JWT and checks nothing.
// sdjwt.ParseLenient also resolves the disclosures, and an error there must
// not hide the signature checks.
func parseJWT(raw string) (*jwt, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("a JWT must have 3 parts separated by dots")
	}
	var token jwt
	for i, target := range []*map[string]any{&token.Header, &token.Payload} {
		data, err := b64.DecodeString(parts[i])
		if err != nil {
			return nil, fmt.Errorf("part %d is not base64url: %w", i+1, err)
		}
		if err := json.Unmarshal(data, target); err != nil {
			return nil, fmt.Errorf("part %d is not a JSON object: %w", i+1, err)
		}
	}
	return &token, nil
}

// Chain is a dSD-JWT or dSD-JWT+KB split into its components
// (draft-ietf-oauth-delegate-sd-jwt-00 §5.1.1).
type Chain struct {
	IssuerJWT   string
	Disclosures []string
	KBSDJWT     string
	// DelegateDisclosures holds the delegate payload disclosure and the
	// delegate disclosures in wire order.
	DelegateDisclosures []string
	// DelegateKBJWT is empty in a dSD-JWT.
	DelegateKBJWT string
}

var ErrNoDelegation = errors.New("the token has no delegation")

func Split(token string) (*Chain, error) {
	parts := strings.Split(token, "~")
	if len(parts) < 2 {
		return nil, errors.New("the token has no ~ separator")
	}
	body, last := parts[:len(parts)-1], parts[len(parts)-1]
	gap := -1
	for i, part := range body {
		if part != "" {
			continue
		}
		if gap >= 0 {
			return nil, errors.New("the token has more than one empty component")
		}
		gap = i
	}
	if gap < 0 {
		return nil, ErrNoDelegation
	}
	if gap == 0 {
		return nil, errors.New("the token starts with an empty component")
	}
	if gap == len(body)-1 {
		return nil, errors.New("no KB-SD-JWT follows the empty component")
	}
	return &Chain{
		IssuerJWT:           body[0],
		Disclosures:         body[1:gap],
		KBSDJWT:             body[gap+1],
		DelegateDisclosures: body[gap+2:],
		DelegateKBJWT:       last,
	}, nil
}

// sdJWTPart is the input of sd_hash in the KB-SD-JWT.
func (c *Chain) sdJWTPart() string {
	return strings.Join(append([]string{c.IssuerJWT}, c.Disclosures...), "~") + "~"
}

// delegatePart is the input of sd_hash in the delegate KB-JWT.
func (c *Chain) delegatePart() string {
	return strings.Join(append([]string{c.KBSDJWT}, c.DelegateDisclosures...), "~") + "~"
}

func (c *Chain) String() string {
	return c.sdJWTPart() + "~" + c.delegatePart() + c.DelegateKBJWT
}
