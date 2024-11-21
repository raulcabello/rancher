package oidcprovider

import (
	"context"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers/ldap"
	"html/template"
	"net/http"
	"time"
)

type ldapProvider struct {
	provider *ldap.LdapProvider
}

func newLdapProvider(provider *ldap.LdapProvider) *ldapProvider {
	return &ldapProvider{
		provider: provider,
	}
}

// TODO can we reuse existing Login page?
func (l *ldapProvider) ShowLoginPage(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("page").Parse(`
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Rancher LDAP Login</title>
	</head>
	<body>
		<h1>Login with LDAP</h1>
		<form action="` + Host + `/authorize/callback" method="GET">
			<label for="user">User:</label>
			<input type="text" id="user" name="user" required>
			<br><br>
			<label for="pass">Pass:</label>
			<input type="text" id="pass" name="pass" required>
			<br><br>
            <input type="hidden" id="client_id" name="client_id" value="` + ClientID + `">
            <input type="hidden" id="state" name="state" value="` + r.URL.Query().Get("state") + `">
            <input type="hidden" id="nonce" name="nonce" value="` + r.URL.Query().Get("nonce") + `">
            <input type="hidden" id="response_type" name="response_type" value="code">
            <input type="hidden" id="redirect_uri" name="redirect_uri" value="http://localhost:8000">

			<button type="submit">Submit</button>
		</form>
	</body>
	</html>
	`))
	tmpl.Execute(w, nil)
}

func (l *ldapProvider) Login(r *http.Request) (*openid.DefaultSession, error) {
	ctx := context.Background()
	user := r.URL.Query().Get("user")
	pass := r.URL.Query().Get("pass") //TODO not in query string!!!
	login := &v3.BasicLogin{
		Username: user,
		Password: pass,
	}
	userPrincipal, groupsPrincipal, _, err := l.provider.AuthenticateUser(ctx, login)
	if err != nil {
		return nil, err
	}
	var groups []string
	for _, group := range groupsPrincipal {
		groups = append(groups, group.Name)
	}

	var mySession = &openid.DefaultSession{
		Username: userPrincipal.Name, // TODO rancher user name or principal from LDAP??
		Subject:  userPrincipal.Name,
		Claims: &jwt.IDTokenClaims{
			Issuer:      Host,
			Subject:     userPrincipal.Name,
			Audience:    []string{"https://my-client.my-application.com"}, //TODO change!
			ExpiresAt:   time.Now().Add(time.Hour * 6),
			IssuedAt:    time.Now(),
			RequestedAt: time.Now(),
			AuthTime:    time.Now(),
			Extra: map[string]interface{}{
				"groups": groups,
			},
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	}

	return mySession, nil
}
