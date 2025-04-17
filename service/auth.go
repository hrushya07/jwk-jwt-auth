package service

import (
	"crypto/rsa"
	"encoding/json"
	"jwk-jwt-auth/internal/manager"
	"jwk-jwt-auth/model"
)

type IAuthService interface {
	GenerateJwt(user *model.User) (string, error)
	GetPublicKeys() ([]*rsa.PublicKey, error)
	VerifyToken(token string) (*model.User, error)
}

type AuthService struct {
	jwtManager manager.IJwtManager
	jwkManager manager.IJwkManager
}

func NewAuthService(jwtManager manager.IJwtManager, jwkManager manager.IJwkManager) IAuthService {
	return &AuthService{
		jwtManager: jwtManager,
		jwkManager: jwkManager,
	}
}

func (a *AuthService) GenerateJwt(user *model.User) (string, error) {
	var userAsMap = user.ToMap()
	return a.jwtManager.GenerateToken(userAsMap)
}

func (a *AuthService) GetPublicKeys() ([]*rsa.PublicKey, error) {
	return a.jwkManager.GetPublicKeys()
}

func (a *AuthService) VerifyToken(token string) (*model.User, error) {
	claimsInMap, errVerifyingSignature := a.jwtManager.VerifyTokenSignatureAndGetClaims(token)
	if errVerifyingSignature != nil {
		return nil, errVerifyingSignature
	}

	var user *model.User
	userDataInBytes, errMarshallingData := json.Marshal(claimsInMap["claim"])
	if errMarshallingData != nil {
		return nil, errMarshallingData
	}

	errUnmarshallingData := json.Unmarshal(userDataInBytes, &user)
	if errUnmarshallingData != nil {
		return nil, errUnmarshallingData
	}

	return user, nil
}
