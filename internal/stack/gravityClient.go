package stack

import (
	"github.com/agentuity/go-common/gravity/provider"
	"github.com/agentuity/go-common/logger"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type GravityClient struct {
	ep        *channel.Endpoint
	logger    logger.Logger
	config    provider.Configuration
	Connected chan struct{}
	onConnect func(*provider.Configuration) error
}

func (p *GravityClient) Configure(config provider.Configuration) error {
	p.logger.Debug("configuring provider")
	p.config = config
	p.Connected <- struct{}{}
	return p.onConnect(&config)
}

func (p *GravityClient) ProcessInPacket(payload []byte) {
	if p.ep == nil {
		p.logger.Error("ProcessInPacket called but endpoint is nil")
		return
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	view := buffer.NewView(len(payload))
	view.Write(payload)
	pkt.Data().AppendView(view)
	p.ep.InjectInbound(ipv6.ProtocolNumber, pkt)
	// Note: Don't call DecRef here - the netstack will handle the packet lifecycle
}
