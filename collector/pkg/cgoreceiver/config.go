package cgoreceiver

type Config struct {
	SubscribeInfo []SubEvent `mapstructure:"subscribe"`
}

// 订阅的事件类别
type SubEvent struct {
	Category string `mapstructure:"category"`
	Name     string `mapstructure:"name"`
}
