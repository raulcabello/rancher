package client

const (
	OIDCClientSpecType                      = "oidcClientSpec"
	OIDCClientSpecFieldDescription          = "description"
	OIDCClientSpecFieldRedirectURIs         = "redirectURIs"
	OIDCClientSpecFieldRefreshTokenLifeSpan = "refreshTokenLifeSpan"
	OIDCClientSpecFieldTokenLifeSpan        = "tokenLifeSpan"
)

type OIDCClientSpec struct {
	Description          string   `json:"description,omitempty" yaml:"description,omitempty"`
	RedirectURIs         []string `json:"redirectURIs,omitempty" yaml:"redirectURIs,omitempty"`
	RefreshTokenLifeSpan int64    `json:"refreshTokenLifeSpan,omitempty" yaml:"refreshTokenLifeSpan,omitempty"`
	TokenLifeSpan        int64    `json:"tokenLifeSpan,omitempty" yaml:"tokenLifeSpan,omitempty"`
}
