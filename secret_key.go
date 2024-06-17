package jwt

import "sync"

var (
	secretKey []byte
	once      sync.Once
)

func SetSecretKey(key []byte) {
	once.Do(func() { secretKey = key })
}
