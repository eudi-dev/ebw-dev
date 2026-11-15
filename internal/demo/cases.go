// Package demo is the web server of the business wallet demo. It holds the
// agent service, the scripted agent, the verifiers, the scenarios and the
// issuer page.
package demo

import (
	"slices"
	"strings"
	"unicode"

	"github.com/eudi-dev/ebw-dev/internal/dsdjwt"
)

const (
	TypePowerOfAttorney       = "uri:eu.eudi.eu-poa.1"
	TypeEmployeeAuthorisation = "urn:eudi-test:business:employee-authorisation:1"
)

const (
	VariantOK            = "ok"
	VariantOverLimit     = "over_limit"
	VariantExpired       = "expired"
	VariantWrongVerifier = "wrong_verifier"
	VariantTampered      = "tampered"
	// VariantRevoked revokes the credential under the mandate in the wallet
	// before the agent runs.
	VariantRevoked = "revoked"
)

var variants = []string{VariantOK, VariantOverLimit, VariantExpired, VariantWrongVerifier, VariantTampered, VariantRevoked}

type Verifier struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Organisation    string   `json:"organisation"`
	CredentialTypes []string `json:"credential_types"`
	TrustedLists    []string `json:"trusted_lists"`
	Actions         []string `json:"actions"`
	Claims          [][]any  `json:"claims"`
}

type Case struct {
	ID             string `json:"id"`
	Verifier       string `json:"verifier"`
	CredentialType string `json:"credential_type"`
	CredentialName string `json:"credential_name"`
	// Template is the credential template of the wallet for this type.
	Template string `json:"template"`
	// IntendedUse is the registered intended use of the agent service for
	// the mandate request.
	IntendedUse string       `json:"intended_use"`
	Claims      [][]any      `json:"claims"`
	Agent       dsdjwt.Agent `json:"agent"`
	Purpose     string       `json:"purpose"`
	Action      string       `json:"action"`
	Limit       dsdjwt.Limit `json:"limit"`
	// OtherAudience is a second audience of the mandate. The agent never
	// shows it to the verifier of this case.
	OtherAudience string `json:"other_audience"`
	Task          Task   `json:"task"`

	Heading  string `json:"-"`
	Intro    string `json:"-"`
	Place    string `json:"-"`
	Summary  string `json:"-"`
	Service  string `json:"-"`
	Do       string `json:"-"`
	Acting   string `json:"-"`
	Accepted string `json:"-"`
}

// Number is the position of the case on the map.
func (c Case) Number() int {
	return slices.IndexFunc(cases, func(other Case) bool { return other.ID == c.ID }) + 1
}

// Authority is the name of the credential behind the delegation inside a
// sentence. Only the abbreviation EU keeps its capitals.
func (c Case) Authority() string {
	name := c.CredentialName
	if len(name) > 1 && unicode.IsLower(rune(name[1])) {
		name = strings.ToLower(name[:1]) + name[1:]
	}
	return "the " + name
}

type Task struct {
	Description     string `json:"description"`
	Reference       string `json:"reference"`
	Amount          string `json:"amount"`
	OverLimitAmount string `json:"over_limit_amount"`
	Currency        string `json:"currency"`
}

const strangerID = "crate"

var verifiers = map[string]Verifier{
	"bolt": {
		ID:              "bolt",
		Name:            "Bolt Supplies supplier portal",
		Organisation:    "Bolt Supplies B.V.",
		CredentialTypes: []string{TypePowerOfAttorney},
		TrustedLists:    []string{"pub-eaa", "qeaa"},
		Actions:         []string{"order.create"},
		Claims:          [][]any{{"company_statutory_full_name"}, {"euid_reference"}, {"attorney_full_name"}},
	},
	"procurement": {
		ID:              "procurement",
		Name:            "Acme internal procurement API",
		Organisation:    "Acme Logistics GmbH",
		CredentialTypes: []string{TypeEmployeeAuthorisation},
		TrustedLists:    []string{"eaa"},
		Actions:         []string{"invoice.approve"},
		Claims:          [][]any{{"represented_economic_operator"}, {"proxy"}, {"authority"}},
	},
	strangerID: {
		ID:              strangerID,
		Name:            "Crate Trading portal",
		Organisation:    "Crate Trading ApS",
		CredentialTypes: []string{TypePowerOfAttorney, TypeEmployeeAuthorisation},
		TrustedLists:    []string{"pub-eaa", "qeaa", "eaa"},
		Actions:         []string{"order.create", "invoice.approve"},
	},
}

var cases = []Case{
	{ //nolint:gosec // G101 reads the credential type as a secret
		ID:             "supplier",
		Verifier:       "bolt",
		CredentialType: TypePowerOfAttorney,
		CredentialName: "EU power of attorney",
		Template:       "eu-poa",
		IntendedUse:    "supplier-mandate",
		Claims: [][]any{
			{"company_statutory_full_name"}, {"euid_reference"}, {"attorney_full_name"},
			{"scope_of_representation_powers", nil}, {"validity_period_valid_until"},
		},
		Agent:         dsdjwt.Agent{ID: "urn:eudi-test:agent:procurement-1", Name: "Procurement agent", Operator: "Acme Logistics GmbH"},
		Purpose:       "Order packaging material",
		Action:        "order.create",
		Limit:         dsdjwt.Limit{Amount: "5000.00", Currency: "EUR"},
		OtherAudience: "redirect_uri:https://second-supplier.example/openid4vp/response",
		Task: Task{
			Description:     "Order 40 pallets of stretch film from Bolt Supplies B.V.",
			Reference:       "PO-2026-0471",
			Amount:          "1840.00",
			OverLimitAmount: "7500.00",
			Currency:        "EUR",
		},
		Heading:  "Order at Bolt Supplies",
		Intro:    "The AI agent of Acme places an order in the supplier portal of Bolt Supplies B.V. Its delegation comes from the EU power of attorney.",
		Place:    "Bolt Supplies B.V.",
		Summary:  "The agent orders stretch film for 1840.00 EUR. Its delegation comes from the EU power of attorney.",
		Service:  "Supplier portal",
		Do:       "Place the order",
		Acting:   "The agent orders 40 pallets of stretch film for 1840.00 EUR. It shows the delegation to the supplier portal of Bolt Supplies.",
		Accepted: "The supplier portal accepted the order PO-2026-0471.",
	},
	{
		ID:             "internal",
		Verifier:       "procurement",
		CredentialType: TypeEmployeeAuthorisation,
		CredentialName: "Employee authorisation",
		Template:       "employee-authorisation",
		IntendedUse:    "internal-mandate",
		Claims:         [][]any{{"represented_economic_operator"}, {"proxy"}, {"authority"}},
		Agent:          dsdjwt.Agent{ID: "urn:eudi-test:agent:procurement-1", Name: "Procurement agent", Operator: "Acme Logistics GmbH"},
		Purpose:        "Approve supplier invoices",
		Action:         "invoice.approve",
		Limit:          dsdjwt.Limit{Amount: "2500.00", Currency: "EUR"},
		OtherAudience:  "redirect_uri:https://erp.acme.example/openid4vp/response",
		Task: Task{
			Description:     "Approve invoice BS-2026-1187 of Bolt Supplies B.V.",
			Reference:       "BS-2026-1187",
			Amount:          "1840.00",
			OverLimitAmount: "7500.00",
			Currency:        "EUR",
		},
		Heading:  "Invoice approval at Acme",
		Intro:    "The AI agent of Acme approves a supplier invoice in the procurement API of Acme. Its delegation comes from the employee authorisation.",
		Place:    "Acme procurement API",
		Summary:  "The agent approves an invoice of 1840.00 EUR. Its delegation comes from the employee authorisation.",
		Service:  "Procurement API",
		Do:       "Approve the invoice",
		Acting:   "The agent approves invoice BS-2026-1187 for 1840.00 EUR. It shows the delegation to the procurement API of Acme.",
		Accepted: "The procurement API approved invoice BS-2026-1187.",
	},
}

func caseByID(id string) (Case, bool) {
	for _, c := range cases {
		if c.ID == id {
			return c, true
		}
	}
	return Case{}, false
}
