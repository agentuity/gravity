package utils

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/agentuity/go-common/api"
	_logger "github.com/agentuity/go-common/logger"
)

func FindAvailableOpenPort() (int, error) {
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func GetPrivateIPv4() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("failed to get private IPv4: %w", err)
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String(), nil
		}
	}
	return "", fmt.Errorf("no private IPv4 address found")
}

type Endpoint struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

type Response struct {
	Success bool     `json:"success"`
	Message string   `json:"message"`
	Data    Endpoint `json:"data"`
}

func GetDevModeEndpoint(ctx context.Context, logger _logger.Logger, baseUrl string, token string, projectId string, hostname string) (*Endpoint, error) {
	client := api.New(ctx, logger, baseUrl, token)

	var resp Response
	body := map[string]string{
		"hostname": hostname,
	}
	api.Commit = "none"
	api.Project = "CLI"

	if err := client.Do("POST", fmt.Sprintf("/cli/devmode/2/%s", url.PathEscape(projectId)), body, &resp); err != nil {
		return nil, fmt.Errorf("error fetching devmode endpoint: %s", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("error fetching devmode endpoint: %s", resp.Message)
	}
	return &resp.Data, nil
}
