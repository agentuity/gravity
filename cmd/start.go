package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/agentuity/go-common/gravity/provider"
	_logger "github.com/agentuity/go-common/logger"
	cnet "github.com/agentuity/go-common/network"
	csys "github.com/agentuity/go-common/sys"
	"github.com/agentuity/gravity/internal/heartbeat"
	"github.com/agentuity/gravity/internal/stack"
	"github.com/agentuity/gravity/internal/utils"
	"github.com/spf13/cobra"
)

var version string = "dev"

var rootCmd = &cobra.Command{
	Use:   "gravity",
	Short: "Run the gravity client",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		flags := cmd.Flags()

		var logLevel _logger.LogLevel
		logLevelStr, _ := flags.GetString("log-level")
		if logLevelStr == "" {
			logLevel = _logger.GetLevelFromEnv()
		} else {
			switch logLevelStr {
			case "info", "INFO":
				logLevel = _logger.LevelInfo
			case "debug", "DEBUG":
				logLevel = _logger.LevelDebug
			case "warn", "WARN":
				logLevel = _logger.LevelWarn
			case "trace", "TRACE":
				logLevel = _logger.LevelTrace
			case "error", "ERROR":
				logLevel = _logger.LevelError
			default:
				logLevel = _logger.LevelTrace
			}
		}

		logger := _logger.NewConsoleLogger(logLevel)

		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		localPort, _ := flags.GetInt("port")
		orgID, _ := flags.GetString("org-id")
		projectID, _ := flags.GetString("project-id")
		maybePrivateKey, _ := flags.GetString("private-key")
		endpointID, _ := flags.GetString("endpoint-id")
		gravityUrl, _ := flags.GetString("url")
		healthCheck, _ := flags.GetBool("health-check")
		token, _ := flags.GetString("token")

		if token != "" {
			logger.Fatal("The --token flag is no longer supported. Please update your Agentuity CLI to the latest version.")
		}

		ipv4addr, err := utils.GetPrivateIPv4()
		if err != nil {
			logger.Fatal("failed to get private IPv4: %v", err)
		}

		privateKeyPEM, err := loadPrivateKeyPEM(maybePrivateKey)
		if err != nil {
			logger.Fatal("failed to load private key: %v", err)
		}

		block, _ := pem.Decode(privateKeyPEM)
		if block == nil {
			logger.Fatal("no PEM block found in --private-key")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			// Try SEC 1/EC format as fallback
			key, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				logger.Fatal("failed to parse private key: %v (pem length: %d)", err, len(privateKeyPEM))
			}
		}
		privateKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			logger.Fatal("private key is not an ECDSA key")
		}

		agent := stack.AgentMetadata{
			OrgID:      orgID,
			ProjectID:  projectID,
			InstanceID: endpointID,
			PrivateKey: privateKey,
		}

		ipv6Address := cnet.NewIPv6Address(cnet.GetRegion(""), cnet.NetworkHadron, agent.OrgID, agent.InstanceID, ipv4addr)
		proxyPort, err := csys.GetFreePort()
		if err != nil {
			logger.Fatal("failed to find available open port: %v", err)
		}

		urls := stack.UrlsMetadata{
			IPv4Addr:  ipv4addr,
			IPv6Addr:  ipv6Address.String(),
			LocalPort: localPort,
			ProxyPort: proxyPort,
			URL:       gravityUrl,
			Version:   version,
		}

		netStack, linkEP, err := stack.CreateNetworkStack(logger, urls)
		if err != nil {
			logger.Fatal("failed to create network stack: %v", err)
		}
		defer netStack.Close()
		defer linkEP.Close()

		var server *http.Server
		var serverMu sync.Mutex
		provider, client, err := stack.CreateNetworkProvider(ctx, logger, linkEP, urls, agent, func(c *provider.Configuration) error {
			serverMu.Lock()
			oldServer := server
			server = nil
			serverMu.Unlock()
			if oldServer != nil {
				if err := oldServer.Shutdown(ctx); err != nil {
					logger.Error("failed to shutdown server: %v", err)
				}
			}
			tlsConfig, err := stack.GenerateCertificate(ctx, logger, c.MachineCertBundle)
			if err != nil {
				return fmt.Errorf("failed to generate certificate: %w", err)
			}
			newServer, err := stack.StartServer(ctx, logger, tlsConfig, urls)
			if err != nil {
				return fmt.Errorf("failed to start server: %w", err)
			}
			serverMu.Lock()
			server = newServer
			serverMu.Unlock()
			return nil
		})
		if err != nil {
			logger.Fatal("failed to create network provider: %v", err)
		}

		// Wait for provider connection
		select {
		case <-ctx.Done():
			logger.Fatal("context done: %v", ctx.Err())
		case <-time.After(time.Second * 10):
			logger.Error("timed out waiting for provider connection")
			os.Exit(1)
		case <-provider.Connected:
			logger.Debug("✅ Connected to Gravity! Proxy is ready.")
			break
		}

		// Start heartbeat server for health monitoring (only if --health-check is enabled)
		if healthCheck {
			heartbeatServer, err := heartbeat.NewServer(logger)
			if err != nil {
				logger.Fatal("failed to create heartbeat server: %v", err)
			}
			defer heartbeatServer.Shutdown()

			// Print heartbeat port to stdout so the dev command can read it
			fmt.Printf("HEARTBEAT_PORT=%d\n", heartbeatServer.Port())

			go func() {
				if err := heartbeatServer.Start(ctx); err != nil {
					logger.Error("heartbeat server error: %v", err)
				}
			}()
		}

		// Handle disconnection and reconnection (simplified)
		go func() {
			logger.Debug("waiting on provider disconnect")
			client.Disconnected(ctx)
			logger.Debug("Disconnected from Gravity")
		}()

		// Wait for context cancellation
		<-ctx.Done()
		logger.Debug("Shutting down...")

		// Cleanup
		if err := client.Close(); err != nil {
			logger.Error("error closing gravity client: %v", err)
		}

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		serverMu.Lock()
		serverToShutdown := server
		server = nil
		serverMu.Unlock()
		if serverToShutdown != nil {
			if err := serverToShutdown.Shutdown(shutdownCtx); err != nil {
				logger.Error("error shutting down proxy server: %v", err)
			}
		}
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version)
	},
}

func Execute() {
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				version = s.Value
			}
		}
	}
	if sha := os.Getenv("GIT_SHA"); sha != "" {
		version = sha
	}
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.DisableSuggestions = true
	rootCmd.DisableAutoGenTag = true

	rootCmd.Flags().IntP("port", "p", 3500, "Local port for the proxy")
	rootCmd.Flags().StringP("org-id", "o", os.Getenv("AGENTUITY_CLOUD_ORG_ID"), "Organization ID")
	rootCmd.Flags().StringP("project-id", "i", os.Getenv("AGENTUITY_CLOUD_PROJECT_ID"), "Project ID")
	rootCmd.Flags().StringP("token", "t", os.Getenv("AGENTUITY_SDK_KEY"), "Project SDK Key")
	rootCmd.Flags().StringP("endpoint-id", "e", "", "The endpoint id")
	rootCmd.Flags().StringP("url", "u", "grpc://devmode.agentuity.com", "The gravity url")
	rootCmd.Flags().String("log-level", "", "The log level to use")
	rootCmd.Flags().Bool("health-check", false, "Enable health check server for heartbeat monitoring")
	rootCmd.Flags().String("private-key", "", "EC private key for authentication (PEM string, base64-encoded PEM, or file path)")

	// Mark required flags that must be passed in
	rootCmd.MarkFlagRequired("endpoint-id")
	rootCmd.MarkFlagRequired("private-key")
}

// loadPrivateKeyPEM loads a private key from various formats:
// - PEM-encoded string (starts with "-----BEGIN")
// - Base64-encoded PEM
// - File path containing PEM data
func loadPrivateKeyPEM(input string) ([]byte, error) {
	if input == "" {
		return nil, fmt.Errorf("private key is required")
	}

	// Check if it's already PEM format
	if strings.HasPrefix(strings.TrimSpace(input), "-----BEGIN") {
		return []byte(input), nil
	}

	// Check if it's a file path
	if data, err := os.ReadFile(input); err == nil {
		if strings.HasPrefix(strings.TrimSpace(string(data)), "-----BEGIN") {
			return data, nil
		}
		// File contains base64
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err == nil && strings.HasPrefix(string(decoded), "-----BEGIN") {
			return decoded, nil
		}
		return nil, fmt.Errorf("file does not contain valid PEM or base64-encoded PEM")
	}

	// Try base64 decode
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(input))
	if err != nil {
		return nil, fmt.Errorf("input is not valid PEM, base64, or file path: %w", err)
	}
	if !strings.HasPrefix(string(decoded), "-----BEGIN") {
		return nil, fmt.Errorf("base64-decoded content is not valid PEM")
	}
	return decoded, nil
}
