package trust

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/ebw-dev/internal/dsdjwt"
)

// StatusReference reads the Token Status List reference from the claims of a
// credential (draft-ietf-oauth-status-list-21). It returns dsdjwt.ErrNoStatus
// for a credential without one.
func StatusReference(claims map[string]any) (string, int, error) {
	status, _ := claims["status"].(map[string]any)
	reference, ok := status["status_list"].(map[string]any)
	if !ok {
		return "", 0, dsdjwt.ErrNoStatus
	}
	uri, _ := reference["uri"].(string)
	index, isNumber := reference["idx"].(float64)
	if uri == "" || !isNumber || index < 0 || index != math.Trunc(index) || index > math.MaxInt32 {
		return "", 0, errors.New("status.status_list must have uri and a whole number idx")
	}
	return uri, int(index), nil
}

// CheckStatus returns a status checker for dsdjwt. It reads the Token Status
// List entry of the credential (draft-ietf-oauth-status-list-21). The status
// list token must be signed under a revocation certificate of the named lists.
func (s *Store) CheckStatus(ctx context.Context, lists []string, now time.Time) func(claims map[string]any) error {
	return func(claims map[string]any) error {
		uri, index, err := StatusReference(claims)
		if err != nil {
			return err
		}
		snap, err := s.snapshot()
		if err != nil {
			return err
		}
		location, err := url.Parse(uri)
		if err != nil {
			return fmt.Errorf("status list URI: %w", err)
		}
		// The verifier fetches only from the wallet that published the
		// trusted lists. A credential cannot point it at another host.
		if origin := location.Scheme + "://" + location.Host; !slices.Contains(snap.origins, origin) {
			return fmt.Errorf("the status list at %s is outside the wallet", origin)
		}
		token, err := get(ctx, snap.statusClient, uri)
		if err != nil {
			return fmt.Errorf("loading the status list: %w", err)
		}
		anchors := snap.anchors(lists, func(l *List) []*x509.Certificate { return l.Revocation })
		value, err := statusValue(strings.TrimSpace(string(token)), anchors, uri, index, now)
		if err != nil {
			return err
		}
		switch value {
		case 0:
			return nil
		case 1:
			return errors.New("the issuer has revoked this credential (status 1)")
		case 2:
			return errors.New("the issuer has suspended this credential (status 2)")
		}
		return fmt.Errorf("the status list gives this credential the status %d", value)
	}
}

func statusValue(token string, anchors []*x509.Certificate, uri string, index int, now time.Time) (int, error) {
	header, payload, err := verifyX5C(token, anchors, now)
	if err != nil {
		return 0, fmt.Errorf("status list token: %w", err)
	}
	if header["typ"] != "statuslist+jwt" {
		return 0, fmt.Errorf("the status list token has the typ %v", header["typ"])
	}
	var claims struct {
		Subject string `json:"sub"`
		Expires int64  `json:"exp"`
		List    struct {
			Bits int    `json:"bits"`
			Data string `json:"lst"`
		} `json:"status_list"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, fmt.Errorf("status list token: %w", err)
	}
	if claims.Subject != uri {
		return 0, fmt.Errorf("the status list token is for %q", claims.Subject)
	}
	if claims.Expires != 0 && !now.Before(time.Unix(claims.Expires, 0)) {
		return 0, errors.New("the status list token is expired")
	}
	bits := claims.List.Bits
	if bits != 1 && bits != 2 && bits != 4 && bits != 8 {
		return 0, fmt.Errorf("unsupported status size of %d bits", bits)
	}
	compressed, err := base64.RawURLEncoding.DecodeString(claims.List.Data)
	if err != nil {
		return 0, fmt.Errorf("status list: %w", err)
	}
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return 0, fmt.Errorf("status list: %w", err)
	}
	list, err := io.ReadAll(io.LimitReader(reader, 16<<20))
	if err != nil {
		return 0, fmt.Errorf("status list: %w", err)
	}
	position := index * bits
	if position/8 >= len(list) {
		return 0, fmt.Errorf("the status list has no entry %d", index)
	}
	return int(list[position/8]>>(position%8)) & (1<<bits - 1), nil
}
