package wallettest

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/ebw-dev/internal/dsdjwt"
)

func writeJSON(rw http.ResponseWriter, status int, value any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(value)
}

func writeError(rw http.ResponseWriter, status int, code, description string) {
	writeJSON(rw, status, map[string]string{"error": code, "error_description": description})
}

func (w *Wallet) issueAccessCertificate(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Identifier string   `json:"identifier"`
		Service    string   `json:"serviceIdentifier"`
		CSR        string   `json:"csr"`
		DNSNames   []string `json:"dnsNames"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Identifier == "" || body.Service == "" {
		writeError(rw, http.StatusBadRequest, "invalid_request", "identifier and serviceIdentifier are required")
		return
	}
	block, _ := pem.Decode([]byte(body.CSR))
	if block == nil {
		writeError(rw, http.StatusBadRequest, "invalid_request", "the CSR is not a PEM certificate request")
		return
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err == nil {
		err = request.CheckSignature()
	}
	if err != nil {
		writeError(rw, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	w.mu.Lock()
	serial++
	number := serial
	w.mu.Unlock()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(number),
		Subject:      request.Subject,
		DNSNames:     body.DNSNames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, w.access, request.PublicKey, w.accessKey)
	if err != nil {
		writeError(rw, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(rw, http.StatusCreated, map[string]any{
		"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"chain":       []string{},
		"clientIds":   []string{hashClientID(der)},
	})
}

func hashClientID(der []byte) string {
	hash := sha256.Sum256(der)
	return "x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:])
}

func (w *Wallet) issueRegistrationCertificate(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Identifier  string `json:"identifier"`
		IntendedUse string `json:"intendedUseIdentifier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Identifier == "" || body.IntendedUse == "" {
		writeError(rw, http.StatusBadRequest, "invalid_request", "identifier and intendedUseIdentifier are required")
		return
	}
	token, err := dsdjwt.SignES256(w.accessKey,
		map[string]any{"alg": "ES256", "typ": "rc-wrp+jwt"},
		map[string]any{"sub": body.Identifier, "intended_use_id": body.IntendedUse, "iat": time.Now().Unix()})
	if err != nil {
		writeError(rw, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	info, _ := json.Marshal([]map[string]string{{
		"format": "registration_cert",
		"data":   base64.RawURLEncoding.EncodeToString([]byte(token)),
	}})
	writeJSON(rw, http.StatusCreated, map[string]string{"registrationCertificate": token, "verifierInfo": string(info)})
}

// signedRequest holds the claims of a request object that the wallet reads.
type signedRequest struct {
	ClientID     string `json:"client_id"`
	ResponseMode string `json:"response_mode"`
	ResponseURI  string `json:"response_uri"`
	Nonce        string `json:"nonce"`
	State        string `json:"state"`
	Expires      int64  `json:"exp"`
	Query        struct {
		Credentials []struct {
			ID   string `json:"id"`
			Meta struct {
				Types []string `json:"vct_values"`
			} `json:"meta"`
		} `json:"credentials"`
	} `json:"dcql_query"`
	TransactionData []string          `json:"transaction_data"`
	VerifierInfo    []json.RawMessage `json:"verifier_info"`
}

// readRequest checks a request object with the client identifier prefix
// x509_hash (OpenID4VP 1.0 §5.9.3 and §5.10). The leaf certificate must come
// from the access CA of this wallet.
func (w *Wallet) readRequest(clientID, token string) (*signedRequest, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("the request is not a signed request object")
	}
	var header struct {
		Algorithm string   `json:"alg"`
		Type      string   `json:"typ"`
		Chain     []string `json:"x5c"`
	}
	if err := decodePart(parts[0], &header); err != nil {
		return nil, err
	}
	if header.Algorithm != "ES256" || header.Type != "oauth-authz-req+jwt" || len(header.Chain) == 0 {
		return nil, errors.New("the request object needs alg ES256, typ oauth-authz-req+jwt and x5c")
	}
	der, err := base64.StdEncoding.DecodeString(header.Chain[0])
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := leaf.CheckSignatureFrom(w.access); err != nil {
		return nil, fmt.Errorf("the access certificate is not from this wallet: %w", err)
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if !ok || err != nil || len(signature) != 64 {
		return nil, errors.New("the request object has no ES256 signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return nil, errors.New("the signature of the request object does not match the access certificate")
	}
	request := &signedRequest{}
	if err := decodePart(parts[1], request); err != nil {
		return nil, err
	}
	switch {
	case clientID != hashClientID(der) || request.ClientID != clientID:
		return nil, errors.New("client_id is not the x509_hash of the access certificate")
	case request.ResponseMode != "direct_post" || request.ResponseURI == "" || request.Nonce == "":
		return nil, errors.New("the request needs response_mode direct_post, response_uri and nonce")
	case time.Now().Unix() > request.Expires:
		return nil, errors.New("the request object expired")
	case len(request.VerifierInfo) == 0:
		return nil, errors.New("the request carries no registration certificate")
	}
	return request, nil
}

func decodePart(part string, into any) error {
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, into)
}

func (w *Wallet) serveCredentials(rw http.ResponseWriter, _ *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	credentials := []map[string]any{}
	for _, stored := range w.credentials {
		status := 0
		if w.revoked[stored.Index] {
			status = 1
		}
		credentials = append(credentials, map[string]any{
			"id":         stored.ID,
			"vct":        stored.Type,
			"issued_at":  stored.Issued.UTC().Format(time.RFC3339Nano),
			"valid_from": stored.Issued.UTC().Format(time.RFC3339Nano),
			"expires_at": stored.Issued.AddDate(1, 0, 0).UTC().Format(time.RFC3339Nano),
			"status":     map[string]any{"uri": w.URL + "/api/statuslist", "idx": stored.Index, "status": status},
		})
	}
	writeJSON(rw, http.StatusOK, credentials)
}

func (w *Wallet) setStatus(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Status int `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(rw, http.StatusBadRequest, "invalid_request", "the body is not valid JSON")
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, stored := range w.credentials {
		if stored.ID == r.PathValue("id") {
			w.revoked[stored.Index] = body.Status != 0
			writeJSON(rw, http.StatusOK, map[string]int{"index": stored.Index, "status": body.Status})
			return
		}
	}
	writeError(rw, http.StatusNotFound, "not_found", "credential not found")
}

func (w *Wallet) issueFromTemplate(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Template string `json:"template"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	w.mu.Lock()
	defer w.mu.Unlock()
	known, ok := w.templates[body.Template]
	if !ok {
		writeError(rw, http.StatusNotFound, "not_found", "template not found")
		return
	}
	index := w.issue(known.list, known.credentialType, known.claims)
	writeJSON(rw, http.StatusCreated, map[string]any{"id": fmt.Sprintf("credential-%d", index), "status_list_idx": index})
}

// createOffer answers like the issuer of the business wallet with a
// pre-authorized credential offer (OpenID4VCI 1.0 §4.1).
func (w *Wallet) createOffer(rw http.ResponseWriter, r *http.Request) {
	configuration := r.URL.Query().Get("credential")
	w.mu.Lock()
	known := slices.Contains(w.configurations, configuration)
	w.offers = append(w.offers, configuration)
	id := fmt.Sprintf("offer-%d", len(w.offers))
	w.mu.Unlock()
	if !known {
		writeError(rw, http.StatusBadRequest, "invalid_request", "unknown credential configuration")
		return
	}
	issuer := w.URL + "/issuer"
	offerURI := issuer + "/offer/" + id
	writeJSON(rw, http.StatusCreated, map[string]any{
		"id":         id,
		"issuer":     issuer,
		"offer_uri":  offerURI,
		"scheme_uri": "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(offerURI),
		"dc_api": map[string]any{"digital": map[string]any{"requests": []any{map[string]any{
			"protocol": "openid4vci-v1",
			"data": map[string]any{
				"credential_issuer":            issuer,
				"credential_configuration_ids": []string{configuration},
				"grants": map[string]any{"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
					"pre-authorized_code": "code-" + id,
				}},
			},
		}}}},
	})
}

// Offers returns the credential configurations of the created offers.
func (w *Wallet) Offers() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.offers)
}
