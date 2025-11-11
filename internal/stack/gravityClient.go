package stack

import (
	"context"

	"github.com/agentuity/go-common/gravity/proto"
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
}

func (p *GravityClient) Configure(config provider.Configuration) error {
	p.logger.Debug("configuring provider")
	p.config = config
	p.Connected <- struct{}{}
	return nil
}

func (p *GravityClient) Deprovision(ctx context.Context, resourceID string, reason provider.DeprovisionReason) error {
	return nil
}

func (p *GravityClient) Resources() []*proto.ExistingDeployment {
	return nil
}

func (p *GravityClient) SetMetricsCollector(collector provider.ProjectRuntimeStatsCollector) {
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
