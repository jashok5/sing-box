package atp

import (
	"encoding/binary"

	"github.com/sagernet/sing/common/exceptions"
)

type ErrorCode uint16

const (
	CodeBadRequest   ErrorCode = 1000
	CodeBadVersion   ErrorCode = 1001
	CodeAuthFailed   ErrorCode = 1002
	CodeInvalidFrame ErrorCode = 1003
	CodeFlowControl  ErrorCode = 1004
	CodeTimeout      ErrorCode = 1005
	CodeInternal     ErrorCode = 1006
)

func encodeErrorPayload(code ErrorCode, reason string) ([]byte, error) {
	cb := make([]byte, 2)
	binary.BigEndian.PutUint16(cb, uint16(code))
	return EncodeTLVs([]TLV{{Type: TLVErrorCode, Value: cb}, {Type: TLVErrorReason, Value: []byte(reason)}})
}

func decodeErrorPayload(payload []byte) error {
	m, err := ParseTLVMap(payload)
	if err != nil {
		return err
	}
	if len(m[TLVErrorCode]) == 2 {
		code := binary.BigEndian.Uint16(m[TLVErrorCode])
		reason := string(m[TLVErrorReason])
		return exceptions.New("atp error code=", code, " reason=", reason)
	}
	return exceptions.New("atp error")
}
