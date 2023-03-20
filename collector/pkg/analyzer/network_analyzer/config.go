package network_analyzer

const (
	defaultRequestTimeout        = 1
	defaultConnectTimeout        = 1
	defaultResponseSlowThreshold = 500
)

type Config struct {
	ConnectTimeout int `mapstructure:"connect_timeout"`
	RequestTimeout int `mapstructure:"request_timeout"`
	// unit is ms
	ResponseSlowThreshold int `mapstructure:"response_slow_threshold"`

	EnableConntrack       bool   `mapstructure:"enable_conntrack"`
	ConntrackMaxStateSize int    `mapstructure:"conntrack_max_state_size"`
	ConntrackRateLimit    int    `mapstructure:"conntrack_rate_limit"`
	ProcRoot              string `mapstructure:"proc_root"`

	ProtocolParser      []string         `mapstructure:"protocol_parser"`
	ProtocolConfigs     []ProtocolConfig `mapstructure:"protocol_config,omitempty"`
	UrlClusteringMethod string           `mapstructure:"url_clustering_method"`
}

type ProtocolConfig struct {
	Key            string   `mapstructure:"key,omitempty"`
	Ports          []uint32 `mapstructure:"ports,omitempty"`
	PayloadLength  int      `mapstructure:"payload_length"`
	DisableDiscern bool     `mapstructure:"disable_discern,omitempty"`
	Threshold      int      `mapstructure:"slow_threshold,omitempty"`
}

func (cfg *Config) GetConnectTimeout() int {
	if cfg.ConnectTimeout > 0 {
		return cfg.ConnectTimeout
	} else {
		return defaultConnectTimeout
	}
}

func (cfg *Config) GetRequestTimeout() int {
	if cfg.RequestTimeout > 0 {
		return cfg.RequestTimeout
	} else {
		return defaultRequestTimeout
	}
}

func (cfg *Config) getResponseSlowThreshold() int {
	if cfg.ResponseSlowThreshold > 0 {
		return cfg.ResponseSlowThreshold
	} else {
		return defaultResponseSlowThreshold
	}
}
