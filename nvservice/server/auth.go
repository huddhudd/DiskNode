package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

var errInvalidToken = errors.New("invalid token")

func (s *Server) uidFromRequest(r *http.Request) (uint32, error) {
	token, err := s.authTokenFromRequest(r)
	if err != nil {
		return 0, err
	}
	uid, err := uidFromToken(token)
	if err != nil {
		return 0, err
	}
	return uid, nil
}

func (s *Server) authTokenFromRequest(r *http.Request) (string, error) {
	token := strings.TrimSpace(r.Header.Get("MyAuthorization"))
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("Authorization"))
	}
	if token == "" {
		return "", errInvalidToken
	}
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	if token == "" {
		return "", errInvalidToken
	}
	return token, nil
}

func uidFromToken(token string) (uint32, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return 0, errInvalidToken
	}
	payload := parts[1]
	decoded, err := decodeBase64Segment(payload)
	if err != nil {
		return 0, errInvalidToken
	}
	var body struct {
		UID uint32 `json:"uid"`
	}
	if err := json.Unmarshal(decoded, &body); err != nil {
		return 0, errInvalidToken
	}
	if body.UID == 0 {
		return 0, errInvalidToken
	}
	return body.UID, nil
}

func decodeBase64Segment(seg string) ([]byte, error) {
	if m := len(seg) % 4; m != 0 {
		seg += strings.Repeat("=", 4-m)
	}
	decoded, err := base64.StdEncoding.DecodeString(seg)
	if err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(seg)
}
