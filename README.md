<div align="center">
    <img src=".github/Agentuity.png" alt="Agentuity" width="100"/>
</div>

<br />

# Gravity Client

The gravity client CLI that enables secure tunneling to development endpoints through the Agentuity Gravity network infrastructure.

## Overview

This CLI creates a local proxy server that connects to Agentuity's Gravity network, allowing developers to expose local services through secure IPv6 tunnels with automatic certificate generation and network stack management.

## Features

- **Secure Tunneling**: Establishes encrypted connections through Gravity network
- **Automatic Certificate Management**: Generates and manages TLS certificates
- **IPv6 Support**: Creates IPv6 addresses using Gravity's network infrastructure
- **Development Mode Integration**: Seamlessly connects to Agentuity development endpoints
- **Network Stack Management**: Handles low-level networking with gVisor integration

## Installation

```bash
go build -o gravity .
```

## How It Works

1. **Endpoint Discovery**: Retrieves development endpoint configuration from Agentuity API
2. **Network Setup**: Creates IPv6 address and finds available proxy port
3. **Gravity Provisioning**: Establishes connection to Gravity network infrastructure
4. **Certificate Generation**: Creates TLS certificates for secure communication
5. **Proxy Server**: Starts local proxy server with network stack integration
6. **Connection Management**: Handles reconnection and graceful shutdown

## Dependencies

- Go 1.25.3+
- [Cobra CLI](https://github.com/spf13/cobra) for command-line interface
- [gVisor](https://gvisor.dev/) for network stack management
- Agentuity Go Common libraries for networking and logging

## Development

The project follows standard Go project structure:

- `main.go`: Entry point
- `cmd/`: Command-line interface implementation
- `internal/stack/`: Core networking and proxy functionality
- `internal/utils/`: Utility functions

## License

Part of the Agentuity development toolchain.
