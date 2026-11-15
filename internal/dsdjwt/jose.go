// Package dsdjwt reads, extends and verifies delegation chains in the format
// of docs/chain-format.md (draft-ietf-oauth-delegate-sd-jwt-00).
package dsdjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var b64 = base64.RawURLEncoding

// JWK is a public P-256 key (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func PublicJWK(key *ecdsa.PublicKey) (JWK, error) {
	raw, err := key.Bytes()
	if err != nil {
		return JWK{}, fmt.Errorf("encoding the public key: %w", err)
	}
	if key.Curve != elliptic.P256() || len(raw) != 65 {
		return JWK{}, errors.New("the key is not a P-256 key")
	}
	return JWK{Kty: "EC", Crv: "P-256", X: b64.EncodeToString(raw[1:33]), Y: b64.EncodeToString(raw[33:])}, nil
}

func (j JWK) PublicKey() (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported key type %q with curve %q", j.Kty, j.Crv)
	}
	x, err := b64.DecodeString(j.X)
	if err != nil || len(x) != 32 {
		return nil, errors.New("the x coordinate is not 32 bytes of base64url")
	}
	y, err := b64.DecodeString(j.Y)
	if err != nil || len(y) != 32 {
		return nil, errors.New("the y coordinate is not 32 bytes of base64url")
	}
	point := append(append([]byte{4}, x...), y...)
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("the point is not on P-256: %w", err)
	}
	return key, nil
}

// Thumbprint returns the SHA-256 JWK thumbprint (RFC 7638).
func (j JWK) Thumbprint() string {
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, j.Crv, j.Kty, j.X, j.Y)
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:])
}

// VerifyES256 checks the signature of a JWS in compact serialization. The demo
// signs and accepts only ES256, and sdjwt.Verify accepts every algorithm of
// eudi-dev.
func VerifyES256(compact string, header map[string]any, key *ecdsa.PublicKey) error {
	if alg, _ := header["alg"].(string); alg != "ES256" {
		return fmt.Errorf("unsupported algorithm %q", header["alg"])
	}
	dot := strings.LastIndex(compact, ".")
	if dot < 0 {
		return errors.New("the JWS has no signature")
	}
	signature, err := b64.DecodeString(compact[dot+1:])
	if err != nil || len(signature) != 64 {
		return errors.New("an ES256 signature must be 64 bytes of base64url")
	}
	digest := sha256.Sum256([]byte(compact[:dot]))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return errors.New("the signature does not match the key")
	}
	return nil
}

func SignES256(key *ecdsa.PrivateKey, header, payload any) (string, error) {
	head, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingInput := b64.EncodeToString(head) + "." + b64.EncodeToString(body)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signingInput + "." + b64.EncodeToString(signature), nil
}

func hashASCII(value string) string {
	sum := sha256.Sum256([]byte(value))
	return b64.EncodeToString(sum[:])
}

func jwkFromClaims(claims map[string]any) (JWK, *ecdsa.PublicKey, error) {
	cnf, _ := claims["cnf"].(map[string]any)
	raw, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return JWK{}, nil, errors.New("there is no cnf.jwk")
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return JWK{}, nil, err
	}
	var jwk JWK
	if err := json.Unmarshal(data, &jwk); err != nil {
		return JWK{}, nil, err
	}
	key, err := jwk.PublicKey()
	if err != nil {
		return JWK{}, nil, err
	}
	return jwk, key, nil
}
