package stack

import (
	"net/url"
	"strings"

	"github.com/agentuity/go-common/logger"
)

const gravityPublicCACertProd = `-----BEGIN CERTIFICATE-----
MIIBvDCCAWKgAwIBAgIIQpGyfo9xbKUwCgYIKoZIzj0EAwIwQjELMAkGA1UEBhMC
VVMxFzAVBgNVBAoTDkFnZW50dWl0eSwgSW5jMRowGAYDVQQDExFBZ2VudHVpdHkg
Um9vdCBDQTAeFw0yNTA4MjgyMDAyNDJaFw0zNTA4MjgyMTAyNDJaMEIxCzAJBgNV
BAYTAlVTMRcwFQYDVQQKEw5BZ2VudHVpdHksIEluYzEaMBgGA1UEAxMRQWdlbnR1
aXR5IFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASuQLIe47OC2EtE
3cwkXJ3siuBeoi5FuJ5wmny1BqA60FrHqHnCiYHIZSyv79WvGs6NAxlJsCQbBtcE
FNvrFfUso0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQURmQweSNnxsTZ/ckG+A08IW7S+fwwCgYIKoZIzj0EAwIDSAAwRQIhAJzN
k5ZrKQPMCAEh1zBuUbWTcuRCnqdk583gcCBkUo58AiBny+nX/KLE46z1B1NK8qg9
/K75YibTFYFFQAXMF10aNg==
-----END CERTIFICATE-----`

const gravityPublicCACertDev = `-----BEGIN CERTIFICATE-----
MIIBtTCCAVugAwIBAgIBATAKBggqhkjOPQQDAjBCMQswCQYDVQQGEwJVUzEXMBUG
A1UEChMOQWdlbnR1aXR5LCBJbmMxGjAYBgNVBAMTEUFnZW50dWl0eSBSb290IENB
MB4XDTI1MDgyNzIwNTIxM1oXDTM1MDgyNzIxNTIxM1owQjELMAkGA1UEBhMCVVMx
FzAVBgNVBAoTDkFnZW50dWl0eSwgSW5jMRowGAYDVQQDExFBZ2VudHVpdHkgUm9v
dCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMleqtFE+8V/nC2eUEOEkfX+
SZDT9+QSIr2B2HoCllDVnyzOKZFGxURvr90dKa/SUiwfS6LjZp6xNUv2gP7GOIWj
QjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSg
O9ViNhPYNISETcjqCsgs+TN80TAKBggqhkjOPQQDAgNIADBFAiAPcCANK2aU/Q/t
J4R6Su68r+iGJKpONFOiD3DX3p8oMgIhAI32feTJZwUVkNtjTYBRxoYUdZlyobp1
lTpZE2H0bHCM
-----END CERTIFICATE-----
`

// GravityCACertificate returns the Agentuity gravity CA certificate
func GravityCACertificate(logger logger.Logger, gravityURL string) string {
	// Select the appropriate hash based on the API URL
	if isDevelopmentGravityURL(gravityURL) {
		logger.Debug("Using development CA")
		return gravityPublicCACertDev
	}

	logger.Debug("Using production CA")
	return gravityPublicCACertProd
}

// isDevelopmentGravityURL determines if we're in a development environment based on the API URL
func isDevelopmentGravityURL(apiURL string) bool {
	parsedURL, err := url.Parse(apiURL)
	if err != nil {
		return false
	}

	// Extract hostname, stripping any port
	hostname := parsedURL.Hostname()

	// Exact matches for development environments
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "host.docker" {
		return true
	}

	// Safe suffix check for agentuity.io domain
	if hostname == "agentuity.io" || strings.HasSuffix(hostname, ".agentuity.io") {
		return true
	}

	return false
}
