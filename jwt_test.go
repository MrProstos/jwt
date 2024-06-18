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

	expected := NewJwt(TestPayload{Id: 1, Email: "tests@tests.com"})
	token, err := Encode(expected)
	if err != nil {
		t.Error(err)
	}

	actual, err := Decode[TestPayload](token)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("expected: %v, got: %v", expected, actual)
	}
}
