// Package wallettest is a business wallet for tests. It publishes a wallet
// CA, trusted lists and a status list. It registers relying parties and
// answers OpenID4VP requests as the holder.
package wallettest

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/eudi-dev/ebw-dev/internal/dsdjwt"
	"github.com/eudi-dev/ebw-dev/internal/dsdjwt/dsdtest"
)

const (
	issuanceService   = "https://wallet.test/SvcType/Issuance"
	revocationService = "https://wallet.test/SvcType/Revocation"
)

type Stored struct {
	ID          string
	Type        string
	Index       int
	Issued      time.Time
	IssuerJWT   string
	Disclosures []string
}

type template struct {
	list, credentialType string
	claims               map[string]any
}

type Wallet struct {
	URL       string
	HolderKey *ecdsa.PrivateKey

	server    *httptest.Server
	caKey     *ecdsa.PrivateKey
	ca        *x509.Certificate
	accessKey *ecdsa.PrivateKey
	access    *x509.Certificate
	providers map[string]*provider
	statusKey *ecdsa.PrivateKey
	status    *x509.Certificate

	mu          sync.Mutex
	plain       bool
	revoked     map[int]bool
	credentials []Stored
	next        int
	lists       *Wallet
	templates   map[string]template

	configurations []string
	offers         []string
}

type provider struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

var serial int64

func certificate(name string, key *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool) *x509.Certificate {
	serial++
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		panic(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return parsed
}

func x5c(certificates ...*x509.Certificate) []string {
	chain := make([]string, 0, len(certificates))
	for _, cert := range certificates {
		chain = append(chain, base64.StdEncoding.EncodeToString(cert.Raw))
	}
	return chain
}

// New starts a wallet with the trusted lists pub-eaa and eaa. Call Close at
// the end.
func New() *Wallet {
	wallet := &Wallet{
		HolderKey: dsdtest.NewKey(),
		caKey:     dsdtest.NewKey(),
		accessKey: dsdtest.NewKey(),
		statusKey: dsdtest.NewKey(),
		providers: map[string]*provider{},
		revoked:   map[int]bool{},
		templates: map[string]template{},

		configurations: []string{"ebwoid", "eu-poa", "employee-authorisation"},
	}
	wallet.ca = certificate("Test Wallet CA", wallet.caKey, nil, nil, true)
	wallet.access = certificate("Test Access CA", wallet.accessKey, nil, nil, true)
	wallet.status = certificate("Test Status Signer", wallet.statusKey, nil, nil, false)
	for _, list := range []string{"pub-eaa", "eaa"} {
		key := dsdtest.NewKey()
		wallet.providers[list] = &provider{key: key, cert: certificate("Test "+list+" CA", key, nil, nil, true)}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/certificates/ca", wallet.serveCA)
	mux.HandleFunc("GET /api/trustlists", wallet.serveIndex)
	mux.HandleFunc("GET /api/trustlists/{id}", wallet.serveList)
	mux.HandleFunc("GET /api/statuslist", wallet.serveStatus)
	mux.HandleFunc("POST /api/registrar/access-certificates", wallet.issueAccessCertificate)
	mux.HandleFunc("POST /api/registrar/registration-certificates", wallet.issueRegistrationCertificate)
	mux.HandleFunc("GET /api/credentials", wallet.serveCredentials)
	mux.HandleFunc("POST /api/credentials/{id}/status", wallet.setStatus)
	mux.HandleFunc("POST /api/issue", wallet.issueFromTemplate)
	mux.HandleFunc("POST /issuer/api/offers", wallet.createOffer)
	wallet.server = httptest.NewServer(mux)
	wallet.URL = wallet.server.URL
	return wallet
}

func (w *Wallet) Close() { w.server.Close() }

// SetPlain makes the wallet answer without delegation, like a wallet that
// does not know the transaction data type delegate.
func (w *Wallet) SetPlain(plain bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.plain = plain
}

func (w *Wallet) Revoke(index int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.revoked[index] = true
}

func (w *Wallet) Revoked(index int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.revoked[index]
}

// Issue stores a credential from the issuer of the trusted list. It returns
// the status list index.
func (w *Wallet) Issue(list, credentialType string, claims map[string]any) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.issue(list, credentialType, claims)
}

func (w *Wallet) issue(list, credentialType string, claims map[string]any) int {
	issuer := w.providers[list]
	leafKey := dsdtest.NewKey()
	leaf := certificate("Test "+list+" Provider", leafKey, issuer.cert, issuer.key, false)
	index := w.next
	w.next++
	now := time.Now()
	jwt, disclosures := dsdtest.Issue(dsdtest.Credential{
		IssuerKey: leafKey,
		Header:    map[string]any{"x5c": x5c(leaf)},
		Issuer:    w.URL,
		Type:      credentialType,
		IssuedAt:  now.Add(-time.Minute),
		Expires:   now.Add(12 * time.Hour),
		Holder:    dsdtest.JWK(w.HolderKey),
		Claims:    claims,
		Plain: map[string]any{
			"status": map[string]any{"status_list": map[string]any{"idx": index, "uri": w.URL + "/api/statuslist"}},
		},
	})
	w.credentials = slices.Insert(w.credentials, 0, Stored{
		ID: fmt.Sprintf("credential-%d", index), Type: credentialType, Index: index, Issued: now, IssuerJWT: jwt, Disclosures: disclosures,
	})
	return index
}

// SetTemplate makes POST /api/issue know a credential template.
func (w *Wallet) SetTemplate(name, list, credentialType string, claims map[string]any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.templates[name] = template{list: list, credentialType: credentialType, claims: claims}
}

func (w *Wallet) Credentials() []Stored {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.credentials)
}

// ServeListsOf makes the wallet publish the trusted lists of another wallet.
// The lists are then signed under a foreign CA.
func (w *Wallet) ServeListsOf(other *Wallet) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lists = other
}

func (w *Wallet) serveCA(rw http.ResponseWriter, _ *http.Request) {
	_ = pem.Encode(rw, &pem.Block{Type: "CERTIFICATE", Bytes: w.ca.Raw})
}

func (w *Wallet) serveIndex(rw http.ResponseWriter, _ *http.Request) {
	lists := []map[string]any{}
	for _, id := range []string{"eaa", "pub-eaa"} {
		lists = append(lists, map[string]any{
			"id":                    id,
			"path":                  "/api/trustlists/" + id,
			"url":                   w.URL + "/api/trustlists/" + id,
			"issuanceServiceType":   issuanceService,
			"revocationServiceType": revocationService,
		})
	}
	_ = json.NewEncoder(rw).Encode(map[string]any{"trust_lists": lists})
}

func service(serviceType string, cert *x509.Certificate) map[string]any {
	return map[string]any{"ServiceInformation": map[string]any{
		"ServiceTypeIdentifier": serviceType,
		"ServiceDigitalIdentity": map[string]any{
			"X509Certificates": []any{map[string]any{"val": base64.StdEncoding.EncodeToString(cert.Raw)}},
		},
	}}
}

func (w *Wallet) serveList(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	other := w.lists
	w.mu.Unlock()
	if other != nil {
		other.serveList(rw, r)
		return
	}
	issuer, ok := w.providers[r.PathValue("id")]
	if !ok {
		http.NotFound(rw, r)
		return
	}
	signerKey := dsdtest.NewKey()
	signer := certificate("Test List Signer", signerKey, w.ca, w.caKey, false)
	token, err := dsdjwt.SignES256(signerKey,
		map[string]any{"alg": "ES256", "x5c": x5c(signer)},
		map[string]any{"LoTE": map[string]any{
			"ListAndSchemeInformation": map[string]any{
				"LoTEType":   "https://wallet.test/LoTEType/" + r.PathValue("id"),
				"NextUpdate": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			},
			"TrustedEntitiesList": []any{map[string]any{
				"TrustedEntityServices": []any{
					service(issuanceService, issuer.cert),
					service(revocationService, w.status),
				},
			}},
		}})
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = rw.Write([]byte(token))
}

func (w *Wallet) serveStatus(rw http.ResponseWriter, _ *http.Request) {
	w.mu.Lock()
	bits := make([]byte, 32)
	for index := range w.revoked {
		bits[index/8] |= 1 << (index % 8)
	}
	w.mu.Unlock()
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	_, _ = writer.Write(bits)
	_ = writer.Close()
	token, err := dsdjwt.SignES256(w.statusKey,
		map[string]any{"alg": "ES256", "typ": "statuslist+jwt", "x5c": x5c(w.status)},
		map[string]any{
			"sub": w.URL + "/api/statuslist",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"status_list": map[string]any{
				"bits": 1,
				"lst":  base64.RawURLEncoding.EncodeToString(compressed.Bytes()),
			},
		})
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = rw.Write([]byte(token))
}

// Present answers the signed OpenID4VP request of a registered relying party
// as the holder. It posts the response with the client and returns the redirect_uri of the verifier.
func (w *Wallet) Present(client *http.Client, uri string) (string, error) {
	_, rawQuery, _ := strings.Cut(uri, "?")
	params, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", err
	}
	request, err := w.readRequest(params.Get("client_id"), params.Get("request"))
	if err != nil {
		return "", err
	}
	if len(request.TransactionData) == 0 {
		return w.presentPlain(client, request)
	}
	if len(request.Query.Credentials) != 1 {
		return "", errors.New("the request needs one credential query")
	}
	if len(request.TransactionData) != 1 {
		return "", errors.New("the request needs one transaction data entry")
	}
	query := request.Query.Credentials[0]
	w.mu.Lock()
	plain := w.plain
	stored, ok := w.pick(query.Meta.Types)
	w.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("the wallet holds no credential of the types %v", query.Meta.Types)
	}

	entry := request.TransactionData[0]
	now := time.Now()
	var token string
	if plain {
		sdJWT := strings.Join(append([]string{stored.IssuerJWT}, stored.Disclosures...), "~") + "~"
		kbJWT, err := dsdjwt.SignES256(w.HolderKey,
			map[string]any{"typ": "kb+jwt", "alg": "ES256"},
			map[string]any{
				"iat": now.Unix(), "aud": request.ClientID, "nonce": request.Nonce, "sd_hash": dsdtest.Hash(sdJWT),
				"transaction_data_hashes": []string{dsdtest.Hash(entry)},
			})
		if err != nil {
			return "", err
		}
		token = sdJWT + kbJWT
	} else {
		sent, err := decodeEntry(entry)
		if err != nil {
			return "", err
		}
		token = dsdtest.Delegate(dsdtest.Delegation{
			HolderKey: w.HolderKey, IssuerJWT: stored.IssuerJWT, Disclosures: stored.Disclosures,
			Audience: request.ClientID, Nonce: request.Nonce, IssuedAt: now, Sent: sent,
		})
	}
	vpToken, _ := json.Marshal(map[string][]string{query.ID: {token}})
	return post(client, request.ResponseURI, url.Values{"state": {request.State}, "vp_token": {string(vpToken)}})
}

// pick returns the newest credential of the types. Like the business wallet,
// it presents a valid credential before a revoked one. The caller holds the
// lock.
func (w *Wallet) pick(types []string) (Stored, bool) {
	var found *Stored
	for i := range w.credentials {
		candidate := &w.credentials[i]
		if !slices.Contains(types, candidate.Type) {
			continue
		}
		if !w.revoked[candidate.Index] {
			return *candidate, true
		}
		if found == nil {
			found = candidate
		}
	}
	if found == nil {
		return Stored{}, false
	}
	return *found, true
}

// presentPlain answers each credential query with an SD-JWT VC and a KB-JWT.
// It discloses every claim.
func (w *Wallet) presentPlain(client *http.Client, request *signedRequest) (string, error) {
	now := time.Now()
	tokens := map[string][]string{}
	w.mu.Lock()
	for _, query := range request.Query.Credentials {
		stored, ok := w.pick(query.Meta.Types)
		if !ok {
			continue
		}
		tokens[query.ID] = []string{dsdtest.Present(dsdtest.Presentation{
			HolderKey: w.HolderKey, IssuerJWT: stored.IssuerJWT, Disclosures: stored.Disclosures,
			Audience: request.ClientID, Nonce: request.Nonce, IssuedAt: now,
		})}
	}
	w.mu.Unlock()
	form := url.Values{"state": {request.State}}
	if len(tokens) == 0 {
		form.Set("error", "access_denied")
		form.Set("error_description", "The wallet holds no matching credential.")
		return post(client, request.ResponseURI, form)
	}
	vpToken, _ := json.Marshal(tokens)
	form.Set("vp_token", string(vpToken))
	return post(client, request.ResponseURI, form)
}

func post(client *http.Client, responseURI string, form url.Values) (string, error) {
	response, err := client.PostForm(responseURI, form)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	var answer struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the response endpoint answered %s", response.Status)
	}
	if err := json.NewDecoder(response.Body).Decode(&answer); err != nil {
		return "", err
	}
	return answer.RedirectURI, nil
}

func decodeEntry(encoded string) (dsdjwt.TransactionData, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return dsdjwt.TransactionData{}, err
	}
	var entry struct {
		Type        string   `json:"type"`
		Payload     string   `json:"delegate_payload_disclosure"`
		Disclosures []string `json:"delegate_disclosures"`
	}
	if err := json.Unmarshal(data, &entry); err != nil {
		return dsdjwt.TransactionData{}, err
	}
	if entry.Type != "delegate" {
		return dsdjwt.TransactionData{}, fmt.Errorf("unknown transaction data type %q", entry.Type)
	}
	return dsdjwt.TransactionData{Encoded: encoded, PayloadDisclosure: entry.Payload, Disclosures: entry.Disclosures}, nil
}
