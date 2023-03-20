package network_analyzer

import (
	"collector/pkg/analyzer"
	"collector/pkg/consumer"
	"collector/pkg/model"
	"github.com/Kindling-project/kindling/collector/pkg/component"
	"github.com/Kindling-project/kindling/collector/pkg/component/analyzer/network/protocol"
	"github.com/Kindling-project/kindling/collector/pkg/component/analyzer/network/protocol/factory"
	"github.com/Kindling-project/kindling/collector/pkg/model/constnames"
	"math/rand"
	"sync"
	"time"
)

const (
	Network analyzer.Type = "networkanalyzer"
)

type NetworkAnalyzer struct {
	cfg *Config
	// 配置
	nextConsumers []consumer.Consumer
	// 端口对应到哪种协议
	staticPortMap map[uint32]string
	//  每种协议对应的阈值
	slowThresholdMap map[string]int
	// 每种协议对应的协议解析器
	protocolMap map[string]*protocol.ProtocolParser
	// 解析函数
	parserFactory *factory.ParserFactory
	// 解析器列表
	parsers []*protocol.ProtocolParser
	// 统计数据
	dataGroupPool *DataGroupPool
	// 请求监控Map
	requestMonitor sync.Map
	// tcp消息个数
	tcpMessagePairSize int64
	// udp消息个数
	udpMessagePairSize int64
	// 数据telemetry
	telemetry *component.TelemetryTools
}

func NewNetworkAnalyzer(cfg interface{}, telemetry *component.TelemetryTools, consumers []consumer.Consumer) analyzer.Analyzer {
	config, _ := cfg.(*Config)
	na := &NetworkAnalyzer{
		cfg:           config,
		dataGroupPool: NewDataGroupPool(),
		nextConsumers: consumers,
		telemetry:     telemetry,
	}

	na.parserFactory = factory.NewParserFactory(factory.WithUrlClusteringMethod(na.cfg.UrlClusteringMethod))
	return na
}

func (na *NetworkAnalyzer) ConsumableEvents() []string {
	return []string{
		constnames.ReadEvent,
		constnames.WriteEvent,
		constnames.ReadvEvent,
		constnames.WritevEvent,
		constnames.SendToEvent,
		constnames.RecvFromEvent,
		constnames.SendMsgEvent,
		constnames.RecvMsgEvent,
	}
}

func (na *NetworkAnalyzer) Start() error {
	// TODO When import multi annalyzers, this part should move to factory. The metric will relate with analyzers.
	//newSelfMetrics(na.telemetry.MeterProvider, na)

	//go na.consumerFdNoReusingTrace()

	// 记录每个协议的配置端口对应的协议
	na.staticPortMap = map[uint32]string{}
	for _, config := range na.cfg.ProtocolConfigs {
		for _, port := range config.Ports {
			na.staticPortMap[port] = config.Key
		}
	}

	// 慢阈值map
	na.slowThresholdMap = map[string]int{}
	disableDisernProtocols := map[string]bool{}
	for _, config := range na.cfg.ProtocolConfigs {
		protocol.SetPayLoadLength(config.Key, config.PayloadLength)
		na.slowThresholdMap[config.Key] = config.Threshold
		disableDisernProtocols[config.Key] = config.DisableDiscern
	}

	// 协议map
	na.protocolMap = map[string]*protocol.ProtocolParser{}
	parsers := make([]*protocol.ProtocolParser, 0)
	for _, protocol := range na.cfg.ProtocolParser {
		protocolparser := na.parserFactory.GetParser(protocol)
		if protocolparser != nil {
			na.protocolMap[protocol] = protocolparser
			disableDisern, ok := disableDisernProtocols[protocol]
			if !ok || !disableDisern {
				parsers = append(parsers, protocolparser)
			}
		}
	}
	// Add Generic Last
	parsers = append(parsers, na.parserFactory.GetGenericParser())
	na.parsers = parsers

	rand.Seed(time.Now().UnixNano())
	return nil
}

func (na *NetworkAnalyzer) Shutdown() error {
	// TODO: implement
	return nil
}

func (na *NetworkAnalyzer) Type() analyzer.Type {
	return Network
}

func (na *NetworkAnalyzer) ConsumeEvent(evt *model.Event) error {
	// 如果类别不是网络，则直接丢弃
	if evt.Category != model.Category_CAT_NET {
		return nil
	}

	ctx := evt.GetCtx()
	if ctx == nil || ctx.GetThreadInfo() == nil {
		return nil
	}
	fd := ctx.GetFdInfo()
	if fd == nil {
		return nil
	}

	if fd.GetSip() == nil {
		return nil
	}

	// if not dns and udp == 1, return
	// 如果不是dns且协议是udp的直接丢弃
	if fd.GetProtocol() == model.L4Proto_UDP {
		if _, ok := na.protocolMap[protocol.DNS]; !ok {
			return nil
		}
	}

	if evt.IsConnect() {
		// connect event
		return na.analyseConnect(evt)
	}

	if evt.GetDataLen() <= 0 || evt.GetResVal() < 0 {
		// TODO: analyse udp
		return nil
	}

	isRequest, err := evt.IsRequest()
	if err != nil {
		return err
	}
	if isRequest {
		return na.analyseRequest(evt)
	} else {
		return na.analyseResponse(evt)
	}
}

func (na *NetworkAnalyzer) analyseConnect(evt *model.Event) error {
	return nil
}

func (na *NetworkAnalyzer) analyseRequest(evt *model.Event) error {
	return nil
}

func (na *NetworkAnalyzer) analyseResponse(evt *model.Event) error {
	return nil
}
