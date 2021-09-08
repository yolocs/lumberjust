package token

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt"
)

type Parser struct {
	AuthorityServiceAccount string
	WantAudience            string

	keysCache atomic.Value
}

// For simplicity, returning the justification as a string.
func (p *Parser) ParseJustificationToken(jtoken string) (string, error) {
	jp := &jwt.Parser{}
	claims := jwt.MapClaims{}
	if _, err := jp.ParseWithClaims(jtoken, claims, func(t *jwt.Token) (interface{}, error) {
		var ok bool

		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing required header field, 'kid' indicating key id")
		}

		claims, ok := t.Claims.(jwt.MapClaims)
		if !ok {
			return nil, errors.New("invalid claims")
		}
		if !claims.VerifyAudience(p.WantAudience, true) {
			return nil, fmt.Errorf("didn't get expected audience %q", p.WantAudience)
		}
		if !claims.VerifyIssuer(p.AuthorityServiceAccount, true) {
			return nil, fmt.Errorf("didn't get expected issuer %q", p.AuthorityServiceAccount)
		}
		if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
			return nil, errors.New("justification token has expired")
		}
		if !claims.VerifyNotBefore(time.Now().Unix(), false) {
			return nil, errors.New("justification token has not reached valid window")
		}

		return p.findKey(kid)
	}); err != nil {
		return "", fmt.Errorf("failed to validate justification token: %w", err)
	}

	j, ok := claims["justification"].(string)
	if !ok || j == "" {
		return "", errors.New("no justification found in the token")
	}

	return j, nil
}

func (p *Parser) findKey(keyID string) (*rsa.PublicKey, error) {
	kmRaw := p.keysCache.Load()
	if kmRaw != nil {
		keysMap, ok := kmRaw.(map[string]*rsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid keys cache")
		}

		if keysMap != nil {
			k, ok := keysMap[keyID]
			if ok {
				return k, nil
			}
		}
	}

	var err error
	keysMap, err := p.refreshKeys()
	if err != nil {
		return nil, err
	}

	if keysMap != nil {
		k, ok := keysMap[keyID]
		if ok {
			return k, nil
		}
	}

	return nil, fmt.Errorf("no public key found for authority %q", p.AuthorityServiceAccount)
}

func (p *Parser) refreshKeys() (map[string]*rsa.PublicKey, error) {
	resp, err := http.DefaultClient.Get(fmt.Sprintf("https://www.googleapis.com/service_accounts/v1/metadata/x509/%s", p.AuthorityServiceAccount))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public keys for authority %q: %w", p.AuthorityServiceAccount, err)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public keys for authority %q: %w", p.AuthorityServiceAccount, err)
	}
	var keysJSON map[string]string
	if err := json.Unmarshal(b, &keysJSON); err != nil {
		return nil, fmt.Errorf("failed to parse public keys for authority %q: %w", p.AuthorityServiceAccount, err)
	}

	keysMap := make(map[string]*rsa.PublicKey)
	for id, key := range keysJSON {
		pk, err := parseRSAPublicKey(key)
		if err != nil {
			// Skip
			log.Printf("failed to parse key id=%s: %v\n", id, err)
			continue
		}
		keysMap[id] = pk
	}

	p.keysCache.Store(keysMap)
	return keysMap, nil
}

func parseRSAPublicKey(pemBlock string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemBlock))
	if block == nil {
		return nil, errors.New("unable to decode PEM block containing PUBLIC KEY")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("unsupported public key")
	}
	return pub, nil
	// log.Println(string(block.Type))
	// pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	// if err != nil {
	// 	return nil, fmt.Errorf("x509.ParsePKIXPublicKey: %w", err)
	// }

	// switch typ := pub.(type) {
	// case *rsa.PublicKey:
	// 	return typ, nil
	// default:
	// 	return nil, fmt.Errorf("unsupported public key type: %T", typ)
	// }
}
