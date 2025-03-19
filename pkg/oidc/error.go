package oidc

import (
	"encoding/json"
	"net/http"
)

type Error struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func writeError(errString string, w http.ResponseWriter, code int) {
	oidcErr := Error{
		Error: errString,
	}
	bytes, err := json.Marshal(&oidcErr)
	if err != nil {
		http.Error(w, "failed to parse error", http.StatusInternalServerError)
	}
	http.Error(w, string(bytes), code)
}

func writeErrorWithDescription(errString string, errDescription string, w http.ResponseWriter, code int) {
	oidcErr := Error{
		Error:            errString,
		ErrorDescription: errDescription,
	}
	bytes, err := json.Marshal(&oidcErr)
	if err != nil {
		http.Error(w, "failed to parse error", http.StatusInternalServerError)
	}
	http.Error(w, string(bytes), code)
}
