package demo

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"time"
)

// OfferType is a credential of the business issuer page. Configuration is the
// credential configuration id in the issuer metadata of the wallet.
type OfferType struct {
	Configuration string `json:"configuration"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	Description   string `json:"description"`
	Rulebook      string `json:"rulebook"`
	Usage         string `json:"usage"`
}

var offerTypes = []OfferType{
	{
		Configuration: "ebwoid", Name: "Business wallet owner identification data", Type: TypeEBWOID,
		Description: "Identifies Acme Logistics GmbH as the owner of the business wallet.",
		Rulebook:    "EBWOID rulebook",
		Usage:       "Used by the bank",
	},
	{
		Configuration: "eu-poa", Name: "EU power of attorney", Type: TypePowerOfAttorney,
		Description: "Shows Alice as the representative of Acme Logistics GmbH. It lists her powers and how long they last.",
		Rulebook:    "EU PoA rulebook",
		Usage:       "Used in case 1, by the notary and by the bank",
	},
	{
		Configuration: "employee-authorisation", Name: "Employee authorisation", Type: TypeEmployeeAuthorisation,
		Description: "Allows an employee of Acme Logistics GmbH to approve invoices up to a limit.",
		Rulebook:    "Test type of ebw-dev",
		Usage:       "Used in case 2",
	},
}

// IssuerOffer is a credential offer of the wallet's issuer (OpenID4VCI 1.0
// §4.1) with the links of the issuer page.
type IssuerOffer struct {
	Configuration string         `json:"configuration"`
	Name          string         `json:"name"`
	WalletURL     string         `json:"wallet_url"`
	SchemeURI     string         `json:"scheme_uri"`
	OfferURI      string         `json:"offer_uri"`
	Issuer        string         `json:"issuer"`
	Offer         map[string]any `json:"offer"`
	DecoderURL    string         `json:"decoder_url"`
}

type Holding struct {
	Configuration string           `json:"configuration"`
	Name          string           `json:"name"`
	Credentials   []HeldCredential `json:"credentials"`
}

type HeldCredential struct {
	ID        string    `json:"id"`
	IssuedAt  time.Time `json:"issued_at"`
	ValidFrom time.Time `json:"valid_from,omitzero"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	Valid     bool      `json:"valid"`
}

// apiWalletCredentials lists the credentials of the issuer page that the
// wallet holds. The wallet does not return to the issuer page after an offer,
// so the page compares 2 of these lists to find the new credential.
func (s *Server) apiWalletCredentials(w http.ResponseWriter, r *http.Request) {
	credentials, err := s.wallet.credentials(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "wallet_unavailable", err.Error())
		return
	}
	now := s.now()
	holdings := make([]Holding, 0, len(offerTypes))
	for _, offer := range offerTypes {
		holding := Holding{Configuration: offer.Configuration, Name: offer.Name, Credentials: []HeldCredential{}}
		for _, c := range credentials {
			if c.Type == offer.Type {
				holding.Credentials = append(holding.Credentials, HeldCredential{
					ID: c.ID, IssuedAt: c.IssuedAt, ValidFrom: c.ValidFrom, ExpiresAt: c.ExpiresAt, Valid: c.valid(now),
				})
			}
		}
		holdings = append(holdings, holding)
	}
	writeJSON(w, http.StatusOK, holdings)
}

func (s *Server) createIssuerOffer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Configuration string `json:"configuration"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	index := slices.IndexFunc(offerTypes, func(o OfferType) bool { return o.Configuration == body.Configuration })
	if index < 0 {
		writeError(w, http.StatusBadRequest, "unknown_credential", "the issuer page has no credential "+body.Configuration)
		return
	}
	offer, err := s.wallet.createOffer(r.Context(), body.Configuration)
	if err != nil {
		writeError(w, http.StatusBadGateway, "wallet_unavailable", err.Error())
		return
	}
	var data map[string]any
	if requests := offer.DCAPI.Digital.Requests; len(requests) > 0 {
		data = requests[0].Data
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, IssuerOffer{
		Configuration: body.Configuration,
		Name:          offerTypes[index].Name,
		WalletURL:     s.config.WalletPublicURL + "/credential-offer?credential_offer_uri=" + url.QueryEscape(offer.OfferURI),
		SchemeURI:     offer.SchemeURI,
		OfferURI:      offer.OfferURI,
		Issuer:        offer.Issuer,
		Offer:         data,
		DecoderURL:    s.decoderURL("openid-credential-offer://?credential_offer=" + url.QueryEscape(string(encoded))),
	})
}
