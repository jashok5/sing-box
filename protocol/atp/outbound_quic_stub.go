//go:build !with_quic

package atp

import (
	"context"

	C "github.com/sagernet/sing-box/constant"
)

func (o *Outbound) newQUICSessionConn(ctx context.Context, resumeTicket string) (*sessionConn, string, error) {
	return nil, "", C.ErrQUICNotIncluded
}
