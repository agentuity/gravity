package stack

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	nicID = 1
	mtu   = 1500
)

type AgentMetadata struct {
	InstanceID string
	OrgID      string
	ProjectID  string
}

type UrlsMetadata struct {
	IPv4Addr  string
	IPv6Addr  string
	ProxyPort int
	LocalPort int
	Token     string
}

func ProvisionGravity(ctx context.Context, logger _logger.Logger, agent AgentMetadata, urls UrlsMetadata) (*proto.ProvisionResponse, error) {

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("error getting hostname: %w", err)
	}
	requestObj := gravity.ProvisionRequest{
		Context:    ctx,
		GravityURL: "grpc://devmode.agentuity.com",
		InstanceID: agent.InstanceID,
		Region:     "unknown",
		Provider:   "other",
		PrivateIP:  urls.IPv4Addr,
		Token:      urls.Token,
		Hostname:   hostname,
		Ephemeral:  true,
		Capabilities: &proto.ClientCapabilities{
			DynamicHostname:       true,
			DynamicProjectRouting: agent.ProjectID,
		},
	}

	logger.Info("Provisioning gravity connection...")
	resp, err := gravity.Provision(requestObj)
	if err != nil {
		return nil, fmt.Errorf("failed to provision: %w", err)
	}

	return resp, nil
}

func GenerateCertificate(_ context.Context, logger _logger.Logger, prov *proto.ProvisionResponse) (*tls.Config, error) {
	// Set up TLS config
	cert, err := tls.X509KeyPair(prov.Certificate, prov.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}
	logger.Info("Loaded certificate: %s", cert.Leaf.Subject.CommonName)

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(prov.CaCertificate) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		RootCAs:          caCertPool,
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.X25519MLKEM768, tls.CurveP256},
		NextProtos:       []string{"h2", "http/1.1"},
	}

	logger.Info("Generated TLS config")

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

	// Start HTTPS proxy server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", urls.ProxyPort),
		TLSConfig:    tlsConfig,
		ReadTimeout:  0,
		WriteTimeout: 0,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	// TODO: call shutdown function on server
	var serverErr error
	go func() {
		logger.Info("Starting HTTPS proxy server on port %d", urls.ProxyPort)
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			serverOnce.Do(func() {
				serverErr = fmt.Errorf("failed to start HTTPS proxy server: %w", err)
			})
			logger.Error("HTTPS proxy server error: %v", err)
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
	provResp *proto.ProvisionResponse,
	urls UrlsMetadata,
	agent AgentMetadata,
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

	prov := GravityClient{}
	prov.logger = logger
	prov.ep = linkEP
	prov.Connected = make(chan struct{}, 1)

	client, err := gravity.New(gravity.GravityConfig{
		Context:       ctx,
		Logger:        logger,
		URL:           "grpc://devmode.agentuity.com",
		ClientName:    "cli/devmode",
		ClientVersion: "dev",
		AuthToken:     provResp.ClientToken,
		Cert:          string(provResp.Certificate),
		Key:           string(provResp.PrivateKey),
		CACert:        string(provResp.CaCertificate),
		InstanceID:    agent.InstanceID,
		ReportStats:   false,
		WorkingDir:    ".",
		ConnectionPoolConfig: &gravity.ConnectionPoolConfig{
			PoolSize:             1,
			StreamsPerConnection: 1,
			AllocationStrategy:   gravity.WeightedRoundRobin,
			HealthCheckInterval:  time.Second * 30,
			FailoverTimeout:      time.Second,
		},
		Capabilities: &proto.ClientCapabilities{
			DynamicHostname:       true,
			DynamicProjectRouting: agent.ProjectID,
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
