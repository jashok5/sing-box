//go:build !with_quic

package atp

import C "github.com/sagernet/sing-box/constant"

func (h *Inbound) startQUIC() error {
	return C.ErrQUICNotIncluded
}
