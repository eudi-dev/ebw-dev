// Package dsdtest plays the issuer and the holder of a delegation chain.
// Tests need no wallet.
package dsdtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/ebw-dev/internal/dsdjwt"
)

func NewKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

func JWK(key *ecdsa.PrivateKey) dsdjwt.JWK {
	jwk, err := dsdjwt.PublicJWK(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	return jwk
}

func Hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type Credential struct {
	IssuerKey *ecdsa.PrivateKey
	Header    map[string]any
	Issuer    string
	Type      string
	IssuedAt  time.Time
	Expires   time.Time
	Holder    dsdjwt.JWK
	// Claims are selectively disclosable. Every array element gets its own
	// disclosure. A claim here replaces the plain claim of the same name, so a
	// test can hide exp or cnf in _sd.
	Claims map[string]any
	Plain  map[string]any
}

// Issue signs the credential. It returns the Issuer-signed JWT and all
// disclosures.
func Issue(credential Credential) (string, []string) {
	var disclosures []string
	var digests []string
	for _, name := range slices.Sorted(maps.Keys(credential.Claims)) {
		value := credential.Claims[name]
		if list, isList := value.([]any); isList {
			placeholders := make([]any, 0, len(list))
			for _, element := range list {
				disclosure := must(dsdjwt.NewDisclosure(element))
				disclosures = append(disclosures, disclosure.Raw)
				placeholders = append(placeholders, map[string]any{"...": disclosure.Digest})
			}
			value = placeholders
		}
		disclosure := must(dsdjwt.NewClaimDisclosure(name, value))
		disclosures = append(disclosures, disclosure.Raw)
		digests = append(digests, disclosure.Digest)
	}
	slices.Sort(digests)
	payload := map[string]any{
		"iss":     credential.Issuer,
		"vct":     credential.Type,
		"iat":     credential.IssuedAt.Unix(),
		"nbf":     credential.IssuedAt.Unix(),
		"exp":     credential.Expires.Unix(),
		"cnf":     map[string]any{"jwk": credential.Holder},
		"_sd":     digests,
		"_sd_alg": "sha-256",
	}
	maps.Copy(payload, credential.Plain)
	for name := range credential.Claims {
		delete(payload, name)
	}
	header := map[string]any{"typ": "dc+sd-jwt", "alg": "ES256"}
	maps.Copy(header, credential.Header)
	return must(dsdjwt.SignES256(credential.IssuerKey, header, payload)), disclosures
}

type Delegation struct {
	HolderKey   *ecdsa.PrivateKey
	IssuerJWT   string
	Disclosures []string
	Audience    string
	Nonce       string
	IssuedAt    time.Time
	Sent        dsdjwt.TransactionData
}

func Delegate(delegation Delegation) string {
	sdJWT := strings.Join(append([]string{delegation.IssuerJWT}, delegation.Disclosures...), "~") + "~"
	kbSDJWT := must(dsdjwt.SignES256(delegation.HolderKey,
		map[string]any{"typ": "kb-sd-jwt+kb", "alg": "ES256"},
		map[string]any{
			"iat":                     delegation.IssuedAt.Unix(),
			"aud":                     delegation.Audience,
			"nonce":                   delegation.Nonce,
			"sd_hash":                 Hash(sdJWT),
			"_sd_alg":                 "sha-256",
			"delegate_payload":        []any{map[string]any{"...": Hash(delegation.Sent.PayloadDisclosure)}},
			"transaction_data_hashes": []string{Hash(delegation.Sent.Encoded)},
		}))
	delegate := append([]string{kbSDJWT, delegation.Sent.PayloadDisclosure}, delegation.Sent.Disclosures...)
	return sdJWT + "~" + strings.Join(delegate, "~") + "~"
}

// Presentation is an SD-JWT+KB without delegation (RFC 9901 §4.3).
type Presentation struct {
	HolderKey   *ecdsa.PrivateKey
	IssuerJWT   string
	Disclosures []string
	Audience    string
	Nonce       string
	IssuedAt    time.Time
	// Extra claims go into the Key Binding JWT, such as transaction_data_hashes.
	Extra map[string]any
}

func Present(presentation Presentation) string {
	sdJWT := strings.Join(append([]string{presentation.IssuerJWT}, presentation.Disclosures...), "~") + "~"
	payload := map[string]any{
		"iat":     presentation.IssuedAt.Unix(),
		"aud":     presentation.Audience,
		"nonce":   presentation.Nonce,
		"sd_hash": Hash(sdJWT),
	}
	maps.Copy(payload, presentation.Extra)
	return sdJWT + must(dsdjwt.SignES256(presentation.HolderKey, map[string]any{"typ": "kb+jwt", "alg": "ES256"}, payload))
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

// Failed returns the names of the failed checks of a report.
func Failed(report *dsdjwt.Report) []string {
	var names []string
	for _, check := range report.FailedChecks() {
		names = append(names, check.Name)
	}
	return names
}
