package jwk

const (
	KtyOKP  = "OKP"
	KtyRSA  = "RSA"
	KtyEC   = "EC"
	UseSig  = "sig"
	CrvEd   = "Ed25519"
	CrvP256 = "P-256"
)

type Key struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type Set struct {
	Keys []Key `json:"keys"`
}
