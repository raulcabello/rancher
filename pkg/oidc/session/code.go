package session

import "github.com/rancher/wrangler/v3/pkg/randomtoken"

type WranglerCodeCreator struct{}

func (w *WranglerCodeCreator) GenerateCode() (string, error) {
	return randomtoken.Generate()
}
