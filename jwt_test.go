package jwt

import (
	"reflect"
	"testing"
)

type TestPayload struct {
	Id    uint   `json:"id"`
	Email string `json:"email"`
}

func TestJwt(t *testing.T) {
	SetSecretKey([]byte("secret"))

	expected := &Token[TestPayload]{
		Header: struct {
			Alg string `json:"alg"`
			Typ string `json:"typ"`
		}{
			Alg: "hs256",
			Typ: "JwtToken",
		},
		Payload: TestPayload{
			Id:    1,
			Email: "tests@tests.com",
		},
	}

	token := NewJwt(expected.Payload).Encode()

	actual := &Token[TestPayload]{}
	if err := NewJwt(actual).Decode(token); err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("expected: %v, got: %v", expected, actual)
	}
}
