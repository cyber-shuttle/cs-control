// The JSON shapes this package's routes read and write, kept in this file alone so clients generate their
// TypeScript types from it with tygo; every other type here is internal.

package oauth

type OAuthConfigResponse struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorizationEndpoint"`
	ClientID              string `json:"clientId"`
	Scope                 string `json:"scope"`
}

type ExchangeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"codeVerifier"`
	RedirectURI  string `json:"redirectUri"`
}

type DeviceResponse struct {
	DeviceCode      string `json:"deviceCode"`
	UserCode        string `json:"userCode"`
	CompleteURI     string `json:"verificationUriComplete"`
	IntervalSeconds int64  `json:"intervalSeconds"`
}

type DevicePollRequest struct {
	DeviceCode string `json:"deviceCode"`
}

type DevicePoll struct {
	Status          string `json:"status"`
	IntervalSeconds int64  `json:"intervalSeconds,omitempty"`
	*TokenResponse  `tstype:",extends"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type TokenResponse struct {
	IDToken          string `json:"idToken"`
	RefreshToken     string `json:"refreshToken,omitempty"`
	ExpiresInSeconds int64  `json:"expiresInSeconds"`
}
