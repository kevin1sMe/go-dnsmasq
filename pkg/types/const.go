package types

const (
	LogLevel              = "LOG_LEVEL"
	Listen                = "DNSMASQ_LISTEN"
	DefaultResolver       = "DNSMASQ_DEFAULT"
	NameServers           = "DNSMASQ_SERVERS"
	StubZone              = "DNSMASQ_STUB"
	HostsFile             = "DNSMASQ_HOSTSFILE"
	HostsDirectory        = "DNSMASQ_DIRECTORY_HOSTSFILES"
	HostsFilePollDuration = "DNSMASQ_POLL"
	SearchDomains         = "DNSMASQ_SEARCH_DOMAINS"
	EnableSearch          = "DNSMASQ_ENABLE_SEARCH"
	ResponseCacheCap      = "DNSMASQ_RCACHE"
	ResponseCacheTTL      = "DNSMASQ_RCACHE_TTL"
	DisableRecursion      = "DNSMASQ_NOREC"
	FwdNdots              = "DNSMASQ_FWD_NDOTS"
	Ndots                 = "DNSMASQ_NDOTS"
	RoundRobin            = "DNSMASQ_RR"
	Systemd               = "DNSMASQ_SYSTEMD"
)
