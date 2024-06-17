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

/**
TODO продумать как вынести secret из глобальной переменной в структуру и при этом сохранить дженерики для Token
*/

const separator = "."

type Token[T any] struct {
	Header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}

	Payload T
}

func NewJwt[T any]() *Token[T] {
	return &Token[T]{
		Header: struct {
			Alg string `json:"alg"`
			Typ string `json:"typ"`
		}{
			Alg: "hs256",
			Typ: "JwtToken",
		},
	}
}

func (t *Token[T]) SetPayload(payload T) *Token[T] {
	t.Payload = payload
	return t
}

func (t *Token[T]) Encode() string {
	rawHeader, rawPayload := t.rawURLEncoding(t.Header), t.rawURLEncoding(t.Payload)
	return fmt.Sprintf("%v.%v.%v", rawHeader, rawPayload, t.createSignature(rawHeader, rawPayload))
}

func (t *Token[T]) Decode(tokenStr string) (*Token[T], error) {
	tokenArr := strings.Split(tokenStr, separator)
	headerStr, payloadStr, signature := tokenArr[0], tokenArr[1], tokenArr[2]

	if signature != t.createSignature(headerStr, payloadStr) {
		return nil, errors.New("invalid token")
	}

	decodePayload, err := base64.RawURLEncoding.DecodeString(payloadStr)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(decodePayload, &t.Payload); err != nil {
		return nil, err
	}

	return t, nil
}

func (t *Token[T]) rawURLEncoding(object any) string {
	raw, _ := json.Marshal(object)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (t *Token[T]) createSignature(header string, payload string) string {
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(fmt.Sprintf("%s%s%s", header, separator, payload)))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
