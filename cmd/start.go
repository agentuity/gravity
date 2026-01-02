package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

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
		token, _ := flags.GetString("token")
		endpointID, _ := flags.GetString("endpoint-id")
		gravityUrl, _ := flags.GetString("url")
		healthCheck, _ := flags.GetBool("health-check")

		ipv4addr, err := utils.GetPrivateIPv4()
		if err != nil {
			logger.Fatal("failed to get private IPv4: %v", err)
		}

		agent := stack.AgentMetadata{
			OrgID:      orgID,
			ProjectID:  projectID,
			InstanceID: endpointID,
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
			Token:     token,
			URL:       gravityUrl,
			Version:   version,
		}

		provResp, err := stack.ProvisionGravity(ctx, logger, agent, urls)
		if err != nil {
			logger.Fatal("failed to provision gravity: %v", err)
		}
		tlsConfig, err := stack.GenerateCertificate(ctx, logger, provResp)
		if err != nil {
			logger.Fatal("failed to generate certificate: %v", err)
		}
		server, err := stack.StartServer(ctx, logger, tlsConfig, urls)
		if err != nil {
			logger.Fatal("failed to start server: %v", err)
		}

		netStack, linkEP, err := stack.CreateNetworkStack(logger, urls)
		if err != nil {
			logger.Fatal("failed to create network stack: %v", err)
		}
		defer netStack.Close()
		defer linkEP.Close()

		provider, client, err := stack.CreateNetworkProvider(ctx, logger, linkEP, provResp, urls, agent)
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
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("error shutting down proxy server: %v", err)
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

	// Mark required flags that must be passed in
	rootCmd.MarkFlagRequired("endpoint-id")
}
