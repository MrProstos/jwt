package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const separator = "."

type Token[T any] struct {
	Header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}

	Payload T
}

func NewJwt[T any](payload T) *Token[T] {
	return &Token[T]{
		Header: struct {
			Alg string `json:"alg"`
			Typ string `json:"typ"`
		}{
			Alg: "hs256",
			Typ: "JwtToken",
		},
		Payload: payload,
	}
}

func Encode[T any](token *Token[T]) (string, error) {
	rawHeader, err := encoding(token.Header)
	if err != nil {
		return "", err
	}

	rawPayload, err := encoding(token.Payload)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%v%s%v%s%v", rawHeader, separator, rawPayload, separator, signature(rawHeader, rawPayload)), nil
}

func Decode[T any](token string) (*Token[T], error) {
	tokenArr := strings.Split(token, separator)
	headerStr, payloadStr, sing := tokenArr[0], tokenArr[1], tokenArr[2]

	if sing != signature(headerStr, payloadStr) {
		return nil, errors.New("invalid token")
	}

	decodePayload, err := base64.RawURLEncoding.DecodeString(payloadStr)
	if err != nil {
		return nil, err
	}

	var payload T
	if err = json.Unmarshal(decodePayload, &payload); err != nil {
		return nil, err
	}

	return NewJwt(payload), nil
}

func encoding(object any) (string, error) {
	raw, err := json.Marshal(object)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func signature(header string, payload string) string {
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(fmt.Sprintf("%s%s%s", header, separator, payload)))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
