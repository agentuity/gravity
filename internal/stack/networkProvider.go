package stack

import (
	"fmt"

	"github.com/agentuity/go-common/gravity"
)

type networkProvider struct {
	client *gravity.GravityClient
}

func (p *networkProvider) RouteTraffic(nets []string) error {
	return nil
}

func (p *networkProvider) UnrouteTraffic() error {
	return nil
}

func (p *networkProvider) Read(buffer []byte) (int, error) {
	return 0, nil
}

func (p *networkProvider) Write(packet []byte) (int, error) {
	if err := p.client.WritePacket(packet); err != nil {
		return 0, err
	}
	return len(packet), nil
}

func (p *networkProvider) Running() bool {
	return true
}

func (p *networkProvider) Start(handler func(packet []byte)) {
	fmt.Println("starting network provider")
}
