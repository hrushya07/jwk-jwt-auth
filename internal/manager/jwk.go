package manager

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

type IJwkManager interface {
	InitializeJwkSet(noOfKeys int) error
	GetAnyPrivateKeyWithKeyId() (*rsa.PrivateKey, string, error)
	GetPublicKeyBy(keyId string) (*rsa.PublicKey, error)
	GetPublicKeys() ([]*rsa.PublicKey, error)
}

type JwkManager struct {
	jwkSet jwk.Set
}

func NewJwkManager() IJwkManager {
	return &JwkManager{}
}

func (j *JwkManager) InitializeJwkSet(noOfKeys int) error {
	set := jwk.NewSet()

	for i := 0; i < noOfKeys; i++ {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}

		key, err := jwk.Import(privateKey)
		if err != nil {
			return fmt.Errorf("failed to import RSA key into JWK: %w", err)
		}

		if errSettingKeyId := key.Set(jwk.KeyIDKey, fmt.Sprintf("key-%d", i)); errSettingKeyId != nil {
			return fmt.Errorf("failed to set key ID: %w", errSettingKeyId)
		}

		if errAddingKeyToSet := set.AddKey(key); errAddingKeyToSet != nil {
			return fmt.Errorf("failed to update key set: %w", err)
		}
	}

	j.jwkSet = set

	return nil
}

func (j *JwkManager) GetAnyPrivateKeyWithKeyId() (*rsa.PrivateKey, string, error) {
	if j.jwkSet == nil || j.jwkSet.Len() == 0 {
		return nil, "", fmt.Errorf("JWK set is empty or not initialized")
	}

	// you can place your logic to fetch random key
	// it could be as simple as randomInt from (0 - j.jwkSet.Len() - 1)
	key, foundKey := j.jwkSet.Key(0)
	if !foundKey {
		return nil, "", fmt.Errorf("key not found in JWK set")
	}

	var rawKey interface{}
	if err := jwk.Export(key, &rawKey); err != nil {
		return nil, "", fmt.Errorf("failed to export raw key: %w", err)
	}

	rsaPrivateKey, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return nil, "", fmt.Errorf("exported key is not an RSA private key")
	}

	var kid string
	if err := key.Get(jwk.KeyIDKey, &kid); err != nil {
		return nil, "", fmt.Errorf("failed to get kid: %w", err)
	}

	return rsaPrivateKey, kid, nil
}

func (j *JwkManager) GetPublicKeyBy(keyId string) (*rsa.PublicKey, error) {
	if j.jwkSet == nil {
		return nil, errors.New("JWK set not initialized")
	}

	key, found := j.jwkSet.LookupKeyID(keyId)
	if !found {
		return nil, fmt.Errorf("no key found with kid: %s", keyId)
	}

	var rawKey interface{}
	if err := jwk.Export(key, &rawKey); err != nil {
		return nil, fmt.Errorf("failed to export raw key: %w", err)
	}

	rsaPrivateKey, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("exported key is not an RSA private key")
	}

	return &rsaPrivateKey.PublicKey, nil
}

func (j *JwkManager) GetPublicKeys() ([]*rsa.PublicKey, error) {
	if j.jwkSet == nil || j.jwkSet.Len() == 0 {
		return nil, errors.New("JWK set is empty or not initialized")
	}

	publicKeys := make([]*rsa.PublicKey, 0)

	for i := 0; i < j.jwkSet.Len(); i++ {
		key, ok := j.jwkSet.Key(i)
		if !ok {
			continue // skip if key not accessible
		}

		var rawKey interface{}
		if err := jwk.Export(key, &rawKey); err != nil {
			continue // skip keys that fail to export
		}

		switch k := rawKey.(type) {
		case *rsa.PrivateKey:
			publicKeys = append(publicKeys, &k.PublicKey)
		case *rsa.PublicKey:
			publicKeys = append(publicKeys, k)
		}
	}

	if len(publicKeys) == 0 {
		return nil, errors.New("no RSA public keys found in JWK set")
	}

	return publicKeys, nil
}
