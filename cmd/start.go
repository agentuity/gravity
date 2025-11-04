package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	_logger "github.com/agentuity/go-common/logger"
	cnet "github.com/agentuity/go-common/network"
	"github.com/agentuity/gravity-proxy/internal/stack"
	"github.com/agentuity/gravity-proxy/internal/utils"
	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the gravity proxy",
	Run: func(cmd *cobra.Command, args []string) {
		logger := _logger.NewConsoleLogger(_logger.LevelTrace)
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		localPort, _ := cmd.Flags().GetInt("localPort")
		orgID, _ := cmd.Flags().GetString("orgID")
		projectID, _ := cmd.Flags().GetString("projectID")
		token, _ := cmd.Flags().GetString("token")

		endpoint, err := utils.GetDevModeEndpoint(ctx, logger, "https://api.agentuity.com", token, projectID, "hostname")
		if err != nil {
			logger.Error("failed to get devmode endpoint: %v", err)
			os.Exit(1)
		}
		instanceID := endpoint.ID

		ipv4addr, err := utils.GetPrivateIPv4()
		if err != nil {
			logger.Error("failed to get private IPv4: %v", err)
			os.Exit(1)
		}

		agent := stack.AgentMetadata{
			OrgID:      orgID,
			InstanceID: instanceID,
			ProjectID:  projectID,
		}

		ipv6Address := cnet.NewIPv6Address(cnet.GetRegion(""), cnet.NetworkHadron, agent.OrgID, agent.InstanceID, ipv4addr)
		proxyPort, err := utils.FindAvailableOpenPort()
		if err != nil {
			logger.Error("failed to find available open port: %v", err)
			os.Exit(1)
		}

		urls := stack.UrlsMetadata{
			IPv4Addr:  ipv4addr,
			IPv6Addr:  ipv6Address.String(),
			LocalPort: localPort,
			ProxyPort: proxyPort,
			Token:     token,
		}

		provResp, err := stack.ProvisionGravity(ctx, logger, agent, urls)
		if err != nil {
			logger.Error("failed to provision gravity: %v", err)
			os.Exit(1)
		}
		tlsConfig, err := stack.GenerateCertificate(ctx, logger, provResp)
		if err != nil {
			logger.Error("failed to generate certificate: %v", err)
			os.Exit(1)
		}
		server, err := stack.StartServer(ctx, logger, tlsConfig, urls)
		if err != nil {
			logger.Error("failed to start server: %v", err)
			os.Exit(1)
		}

		netStack, linkEP, err := stack.CreateNetworkStack(logger, urls)
		if err != nil {
			logger.Error("failed to create network stack: %v", err)
			os.Exit(1)
		}
		defer netStack.Close()
		defer linkEP.Close()

		provider, client, err := stack.CreateNetworkProvider(ctx, logger, linkEP, provResp, urls, agent)
		if err != nil {
			logger.Error("failed to create network provider: %v", err)
			os.Exit(1)
		}

		// Wait for provider connection
		select {
		case <-ctx.Done():
			logger.Error("context done: %v", ctx.Err())
			os.Exit(1)
		case <-time.After(time.Second * 10):
			logger.Error("timed out waiting for provider connection")
			os.Exit(1)
		case <-provider.Connected:
			logger.Info("✅ Connected to Gravity! Proxy is ready.")
			break
		}

		// Handle disconnection and reconnection (simplified)
		go func() {
			logger.Info("waiting on provider disconnect")
			client.Disconnected(ctx)
			logger.Info("Disconnected from Gravity")
		}()

		// Wait for context cancellation
		<-ctx.Done()
		logger.Info("Shutting down...")

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

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := startCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	startCmd.Flags().IntP("localPort", "p", 3500, "Local port for the proxy")
	startCmd.Flags().StringP("orgID", "o", "", "Organization ID")
	startCmd.Flags().StringP("projectID", "i", "", "Project ID")
	startCmd.Flags().StringP("token", "t", "", "API Token")
	// Mark required flags
	startCmd.MarkFlagRequired("orgID")
	startCmd.MarkFlagRequired("projectID")
	startCmd.MarkFlagRequired("localPort")
	startCmd.MarkFlagRequired("token")
}
