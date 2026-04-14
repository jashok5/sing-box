package option

import "github.com/sagernet/sing/common/json/badoption"

type ATPInboundUser struct {
	Name  string `json:"name,omitempty"`
	Token string `json:"token"`
}

type ATPInboundOptions struct {
	ListenOptions
	Users            []ATPInboundUser   `json:"users,omitempty"`
	Token            string             `json:"token,omitempty"`
	Password         string             `json:"password,omitempty"`
	Transport        string             `json:"transport,omitempty"`
	HandshakeTimeout badoption.Duration `json:"handshake_timeout,omitempty"`
	IdleTimeout      badoption.Duration `json:"idle_timeout,omitempty"`
	InboundTLSOptionsContainer
}

type ATPOutboundOptions struct {
	DialerOptions
	ServerOptions
	Token            string             `json:"token"`
	Password         string             `json:"password,omitempty"`
	Transport        string             `json:"transport,omitempty"`
	Protocol         string             `json:"protocol,omitempty"`
	ClientName       string             `json:"client_name,omitempty"`
	Network          NetworkList        `json:"network,omitempty"`
	HandshakeTimeout badoption.Duration `json:"handshake_timeout,omitempty"`
	OutboundTLSOptionsContainer
}
