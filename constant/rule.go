package constant

const (
	RuleTypeDefault = "default"
	RuleTypeLogical = "logical"
)

const (
	LogicalTypeAnd = "and"
	LogicalTypeOr  = "or"
)

const (
	RuleSetTypeInline   = "inline"
	RuleSetTypeLocal    = "local"
	RuleSetTypeRemote   = "remote"
	RuleSetFormatSource = "source"
	RuleSetFormatBinary = "binary"
)

const (
	RuleSetVersion1 = 1 + iota
	RuleSetVersion2
	RuleSetVersion3
	RuleSetVersionCurrent = RuleSetVersion3
)

const (
	RuleActionTypeRoute        = "route"
	RuleActionTypeRouteOptions = "route-options"
	RuleActionTypeDirect       = "direct"
	RuleActionTypeReject       = "reject"
	RuleActionTypeHijackDNS    = "hijack-dns"
	RuleActionTypeReturn       = "return"
	RuleActionTypeSniff        = "sniff"
	RuleActionTypeResolve      = "resolve"
	RuleActionTypePredefined   = "predefined"
)
const (
	RuleActionRejectMethodDefault            = "default"
	RuleActionRejectMethodReset              = "reset"
	RuleActionRejectMethodNetworkUnreachable = "network-unreachable"
	RuleActionRejectMethodHostUnreachable    = "host-unreachable"
	RuleActionRejectMethodPortUnreachable    = "port-unreachable"
	RuleActionRejectMethodDrop               = "drop"
)
