package stack

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/agentuity/go-common/gravity"
	"github.com/agentuity/go-common/gravity/proto"
	"github.com/agentuity/go-common/gravity/provider"
	_logger "github.com/agentuity/go-common/logger"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID      = 1
	mtu        = 1500
	clientName = "cli/devmode"
)

type AgentMetadata struct {
	InstanceID string
	OrgID      string
	ProjectID  string
	PrivateKey *ecdsa.PrivateKey
}

type UrlsMetadata struct {
	IPv4Addr  string
	IPv6Addr  string
	ProxyPort int
	LocalPort int
	Token     string
	URL       string
	Version   string
}

func GenerateCertificate(_ context.Context, logger _logger.Logger, bundle string) (*tls.Config, error) {
	certPEM, caCertPEM, keyPEM, err := parsePEMBundle(bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate bundle: %w", err)
	}

	// Set up TLS config
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	// Parse the certificate to log details
	if len(cert.Certificate) > 0 {
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			cert.Leaf = x509Cert
			logger.Debug("Loaded certificate: CN=%s, SANs=%v, NotBefore=%v, NotAfter=%v",
				x509Cert.Subject.CommonName, x509Cert.DNSNames, x509Cert.NotBefore, x509Cert.NotAfter)
		} else {
			logger.Warn("Failed to parse certificate for logging: %v", err)
		}
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Parse and log CA certificate details
	caCert, err := x509.ParseCertificate(caCertPEM)
	if err == nil {
		logger.Debug("Loaded CA certificate: CN=%s, Issuer=%s", caCert.Subject.CommonName, caCert.Issuer.CommonName)
	} else {
		// Try parsing as PEM
		block, _ := pem.Decode(caCertPEM)
		if block != nil {
			caCert, err = x509.ParseCertificate(block.Bytes)
			if err == nil {
				logger.Debug("Loaded CA certificate (PEM): CN=%s, Issuer=%s", caCert.Subject.CommonName, caCert.Issuer.CommonName)
			}
		}
	}

	tlsConfig := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		RootCAs:          caCertPool,
		ClientCAs:        caCertPool, // Also set ClientCAs for mutual TLS
		ClientAuth:       tls.VerifyClientCertIfGiven,
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.X25519MLKEM768, tls.CurveP256},
		NextProtos:       []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			remoteAddr := "<no-remote>"
			if hello != nil && hello.Conn != nil {
				remoteAddr = hello.Conn.RemoteAddr().String()
			}
			logger.Trace("TLS GetCertificate: ServerName=%s, SupportedProtos=%v, RemoteAddr=%v",
				hello.ServerName, hello.SupportedProtos, remoteAddr)
			return &cert, nil
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			logger.Trace("TLS VerifyPeerCertificate: chains=%d, rawCerts=%d", len(verifiedChains), len(rawCerts))
			if len(rawCerts) > 0 {
				peerCert, err := x509.ParseCertificate(rawCerts[0])
				if err == nil {
					logger.Trace("Peer certificate: CN=%s, SANs=%v", peerCert.Subject.CommonName, peerCert.DNSNames)
				}
			}
			return nil
		},
	}

	logger.Debug("Generated TLS config with certificate logging enabled")

	return tlsConfig, nil
}

func StartServer(ctx context.Context, logger _logger.Logger, tlsConfig *tls.Config, urls UrlsMetadata) (*http.Server, error) {

	// Set up reverse proxy to the agent server
	agentURL := fmt.Sprintf("http://127.0.0.1:%d", urls.LocalPort)
	upstreamURL, err := url.Parse(agentURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse agent URL: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	proxy.FlushInterval = -1
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// Suppress expected context cancellation errors (client disconnect, WebSocket close)
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(r.Context().Err(), context.Canceled) {
			return
		}
		logger.Error("proxy error: %v", err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		logger.Trace("response %s: %d", resp.Request.URL.Path, resp.StatusCode)
		return nil
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", urls.ProxyPort),
		TLSConfig:    tlsConfig,
		ReadTimeout:  0,
		WriteTimeout: 0,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Trace("HTTP request: method=%s, path=%s, proto=%s, remote=%s, tls=%v",
				r.Method, r.URL.Path, r.Proto, r.RemoteAddr, r.TLS != nil)
			if r.TLS != nil {
				logger.Trace("TLS connection: version=%x, cipher=%x, server=%s, negotiated=%s",
					r.TLS.Version, r.TLS.CipherSuite, r.TLS.ServerName, r.TLS.NegotiatedProtocol)
			}
			switch r.URL.Path {
			case "/_health":
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.WriteHeader(http.StatusOK)
				return
			default:
			}
			proxy.ServeHTTP(w, r)
		}),
	}

	var serverOnce sync.Once
	var serverErr error

	// For local development, use HTTP if TLS config is nil
	useTLS := tlsConfig != nil

	go func() {
		if useTLS {
			logger.Debug("Starting HTTPS proxy server on port %d", urls.ProxyPort)
			if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				serverOnce.Do(func() {
					serverErr = fmt.Errorf("failed to start HTTPS proxy server: %w", err)
				})
				logger.Error("HTTPS proxy server error: %v", err)
			}
		} else {
			logger.Debug("Starting HTTP proxy server on port %d (local dev mode)", urls.ProxyPort)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				serverOnce.Do(func() {
					serverErr = fmt.Errorf("failed to start HTTP proxy server: %w", err)
				})
				logger.Error("HTTP proxy server error: %v", err)
			}
		}
	}()
	return server, serverErr
}

func CreateNetworkStack(logger _logger.Logger, urls UrlsMetadata) (*stack.Stack, *channel.Endpoint, error) {

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	linkEP := channel.New(1024, mtu, "")
	if err := s.CreateNIC(nicID, linkEP); err != nil {
		return nil, nil, fmt.Errorf("failed to create NIC: %v", err)
	}
	ipBytes := net.ParseIP(urls.IPv6Addr).To16()
	if ipBytes == nil {
		return nil, nil, fmt.Errorf("failed to parse IPv6 address: %s", urls.IPv6Addr)
	}
	var addr [16]byte
	copy(addr[:], ipBytes)

	if err := s.AddProtocolAddress(nicID,
		tcpip.ProtocolAddress{
			Protocol: ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom16(addr),
				PrefixLen: 64,
			},
		},
		stack.AddressProperties{},
	); err != nil {
		return nil, nil, fmt.Errorf("failed to add protocol address: %v", err)
	}

	// Add default route
	subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 16)), tcpip.MaskFromBytes(make([]byte, 16)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create subnet: %w", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         nicID,
		},
	})

	// Set up TCP forwarder
	fwd := tcp.NewForwarder(s, 1024, 1024, func(r *tcp.ForwarderRequest) {
		wq := new(waiter.Queue)
		ep, err := r.CreateEndpoint(wq)
		if err != nil {
			logger.Error("endpoint creation error: %v", err)
			r.Complete(true)
			return
		}

		r.Complete(false)
		tcpConn := gonet.NewTCPConn(wq, ep)
		go bridgeToLocalTLS(logger, uint(urls.ProxyPort), tcpConn)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	return s, linkEP, nil
}

func CreateNetworkProvider(
	ctx context.Context,
	logger _logger.Logger,
	linkEP *channel.Endpoint,
	urls UrlsMetadata,
	agent AgentMetadata,
	onConnect func(*provider.Configuration) error,
) (*GravityClient, *gravity.GravityClient, error) {

	// Egress pump to send outbound packets to Gravity
	var network networkProvider

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				pkt := linkEP.ReadContext(ctx)
				if pkt == nil {
					continue
				}
				buf := pkt.ToBuffer()
				data := buf.Flatten()
				_, err := network.Write(data)
				pkt.DecRef()
				if err != nil {
					logger.Error("failed to send outbound packet: %v", err)
				}
			}
		}
	}()

	prov := GravityClient{
		onConnect: onConnect,
		logger:    logger,
		ep:        linkEP,
		Connected: make(chan struct{}, 1),
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil, err
	}

	client, err := gravity.New(gravity.GravityConfig{
		Context:         ctx,
		Logger:          logger,
		URL:             urls.URL,
		ClientName:      clientName,
		ClientVersion:   urls.Version,
		InstanceID:      agent.InstanceID,
		ECDSAPrivateKey: agent.PrivateKey,
		CACert:          GravityCACertificate(logger, urls.URL),
		ReportStats:     false,
		WorkingDir:      cwd,
		ConnectionPoolConfig: &gravity.ConnectionPoolConfig{
			PoolSize:             1,
			StreamsPerConnection: 1,
			AllocationStrategy:   gravity.WeightedRoundRobin,
			HealthCheckInterval:  time.Second * 30,
			FailoverTimeout:      time.Second,
		},
		Capabilities: &proto.ClientCapabilities{
			DynamicHostname: true,
			// DynamicProjectRouting: "",
		},
		NetworkInterface:  &network,
		Provider:          &prov,
		IP4Address:        urls.IPv4Addr,
		IP6Address:        urls.IPv6Addr,
		SkipAutoReconnect: true,
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gravity client: %w", err)
	}

	network.client = client

	if err := client.Start(); err != nil {
		// Don't wrap context.Canceled - let it propagate cleanly for graceful shutdown
		if errors.Is(err, context.Canceled) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("failed to start gravity client: %w", err)
	}

	return &prov, client, nil
}

func bridgeToLocalTLS(logger _logger.Logger, proxyPort uint, remote *gonet.TCPConn) {
	defer remote.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	local, err := net.Dial("tcp", addr)
	if err != nil {
		logger.Error("❌ DIAL ERROR: %v", err)
		return
	}
	defer local.Close()

	go func() {
		io.Copy(local, remote)
	}()
	io.Copy(remote, local)
}

// parsePEMBundle parses a PEM bundle containing certificate, CA certificate, and private key.
// Blocks are identified by type, not position.
func parsePEMBundle(bundle string) (cert, caCert, privateKey []byte, err error) {
	data := []byte(bundle)
	var certs []*pem.Block

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			certs = append(certs, block)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			if privateKey != nil {
				return nil, nil, nil, fmt.Errorf("multiple private keys in bundle")
			}
			privateKey = pem.EncodeToMemory(block)
		}

		data = rest
	}

	if privateKey == nil {
		return nil, nil, nil, fmt.Errorf("no private key found in bundle")
	}

	if len(certs) != 2 {
		return nil, nil, nil, fmt.Errorf("expected 2 certificates (cert, ca), got %d", len(certs))
	}

	// Determine which cert is the CA by checking IsCA
	for i, block := range certs {
		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		if x509Cert.IsCA {
			caCert = pem.EncodeToMemory(block)
			cert = pem.EncodeToMemory(certs[1-i])
			break
		}
	}

	if caCert == nil {
		return nil, nil, nil, fmt.Errorf("could not identify CA certificate")
	}

	return cert, caCert, privateKey, nil
}
