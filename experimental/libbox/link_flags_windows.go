//go:build windows

package libbox

import "net"

func linkFlags(rawFlags uint32) net.Flags {
	var f net.Flags
	if rawFlags&uint32(net.FlagUp) != 0 {
		f |= net.FlagUp
	}
	if rawFlags&uint32(net.FlagRunning) != 0 {
		f |= net.FlagRunning
	}
	if rawFlags&uint32(net.FlagBroadcast) != 0 {
		f |= net.FlagBroadcast
	}
	if rawFlags&uint32(net.FlagLoopback) != 0 {
		f |= net.FlagLoopback
	}
	if rawFlags&uint32(net.FlagPointToPoint) != 0 {
		f |= net.FlagPointToPoint
	}
	if rawFlags&uint32(net.FlagMulticast) != 0 {
		f |= net.FlagMulticast
	}
	return f
}
