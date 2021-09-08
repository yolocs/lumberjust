package token

import (
	"testing"
)

func TestParser(t *testing.T) {
	p := &Parser{
		AuthorityServiceAccount: "example@example.iam.gserviceaccount.com",
		WantAudience:            "example.com",
	}

	tk := "somejwt"

	if _, err := p.ParseJustificationToken(tk); err != nil {
		t.Error(err)
	}
}
