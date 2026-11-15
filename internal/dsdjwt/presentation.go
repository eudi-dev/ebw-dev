package dsdjwt

import (
	"errors"
	"fmt"
	"strings"
)

// CheckKeyBindingSDHash is the sd_hash of the Key Binding JWT in an SD-JWT+KB
// presentation without delegation.
const CheckKeyBindingSDHash = "kb_jwt_credential_sd_hash"

// SDJWTExpectation is what the verifier expects in the Key Binding JWT of an
// SD-JWT+KB.
type SDJWTExpectation struct {
	Audience string
	Nonce    string
}

// VerifySDJWT checks an SD-JWT+KB presentation of an SD-JWT VC (RFC 9901
// §7.3). The report has the links credential and presentation.
func VerifySDJWT(token string, expected SDJWTExpectation, opts Options) (*Report, error) {
	report := &Report{Structure: Check{Name: CheckStructure, Result: Pass}}
	defer report.Seal()
	chain, kbJWT, err := splitSDJWT(token)
	if err != nil {
		report.Structure = Check{Name: CheckStructure, Result: Fail, Detail: err.Error()}
		return report, nil
	}
	credential := &Link{Kind: LinkCredential, Signer: "Issuer"}
	presentation := &Link{Kind: LinkPresentation, Signer: "Holder"}
	report.Links = append(report.Links, credential, presentation)
	holderKey := verifyCredential(chain, credential, report, opts)

	kb, err := parseJWT(kbJWT)
	if err != nil {
		presentation.Add(CheckPresentationType, fmt.Errorf("the Key Binding JWT does not parse: %w", err), "")
		presentation.skip("the Key Binding JWT does not parse", CheckHolderSignature, CheckAudience, CheckNonce, CheckIssuedAt, CheckKeyBindingSDHash)
		return report, nil
	}
	presentation.Header, presentation.Claims = kb.Header, kb.Payload
	presentation.Add(CheckPresentationType, equalClaim(kb.Header, "typ", "kb+jwt"), "")
	if holderKey == nil {
		presentation.skip("the holder key is unknown", CheckHolderSignature)
	} else {
		presentation.KeyThumbprint = holderKey.thumbprint
		presentation.Add(CheckHolderSignature, VerifyES256(kbJWT, kb.Header, holderKey.key), "signed with cnf of the credential")
	}
	keyBinding(presentation, kb.Payload, expected.Audience, expected.Nonce, opts)
	presentation.Add(CheckKeyBindingSDHash, equalClaim(kb.Payload, "sd_hash", hashASCII(chain.sdJWTPart())), "")
	return report, nil
}

// splitSDJWT splits <Issuer-signed JWT>~<Disclosure>~...~<KB-JWT> (RFC 9901
// §4). Split reads the empty component of a dSD-JWT and refuses this form.
func splitSDJWT(token string) (*Chain, string, error) {
	parts := strings.Split(token, "~")
	if len(parts) < 2 {
		return nil, "", errors.New("the token has no ~ separator")
	}
	body, kbJWT := parts[:len(parts)-1], parts[len(parts)-1]
	for _, part := range body {
		if part == "" {
			return nil, "", errors.New("the token has an empty component, so it is not an SD-JWT+KB")
		}
	}
	if kbJWT == "" {
		return nil, "", errors.New("the token ends with ~ and has no Key Binding JWT")
	}
	return &Chain{IssuerJWT: body[0], Disclosures: body[1:]}, kbJWT, nil
}
