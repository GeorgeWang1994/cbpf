package tcp_connect_analyzer

import (
	"collector/pkg/analyzer"
	"collector/pkg/consumer"
	"collector/pkg/model"
	"github.com/Kindling-project/kindling/collector/pkg/component"
	"github.com/Kindling-project/kindling/collector/pkg/model/constnames"
	"go.uber.org/zap"
	"time"
)

const (
	TcpMetric analyzer.Type = "tcp_connect_metric_analyzer"
)

type TcpConnectAnalyzer struct {
	config        *Config
	nextConsumers []consumer.Consumer

	eventChannel chan *model.Event
	//connectMonitor *internal.ConnectMonitor

	stopCh chan bool

	telemetry *component.TelemetryTools
}

func New(cfg interface{}, telemetry *component.TelemetryTools, consumers []consumer.Consumer) analyzer.Analyzer {
	config := cfg.(*Config)
	ret := &TcpConnectAnalyzer{
		config:        config,
		nextConsumers: consumers,
		telemetry:     telemetry,
		eventChannel:  make(chan *model.Event, config.ChannelSize),
		stopCh:        make(chan bool),

		//connectMonitor: internal.NewConnectMonitor(telemetry.Logger),
	}
	//newSelfMetrics(telemetry.MeterProvider, ret.connectMonitor)
	return ret
}

func (a *TcpConnectAnalyzer) ConsumableEvents() []string {
	return []string{
		constnames.ConnectEvent,
		constnames.TcpConnectEvent,
		constnames.TcpSetStateEvent,
		constnames.WriteEvent,
		constnames.WritevEvent,
		constnames.SendMsgEvent,
		constnames.SendToEvent,
	}
}

// Start initializes the analyzer
func (a *TcpConnectAnalyzer) Start() error {
	go func() {
		scanTcpStateTicker := time.NewTicker(time.Duration(a.config.WaitEventSecond/3) * time.Second)
		for {
			select {
			case <-scanTcpStateTicker.C:
				a.trimConnectionsWithTcpStat()
			case event := <-a.eventChannel:
				a.consumeChannelEvent(event)
			case <-a.stopCh:
				// Only trim the connections expired. For those unfinished, we leave them
				// unchanged and just shutdown this goroutine.
				a.trimConnectionsWithTcpStat()
				return
			}
		}
	}()
	return nil
}

// ConsumeEvent gets the event from the previous component
func (a *TcpConnectAnalyzer) ConsumeEvent(event *model.Event) error {
	a.eventChannel <- event
	return nil
}

func (a *TcpConnectAnalyzer) consumeChannelEvent(event *model.Event) {
	var (
		connectStats *internal.ConnectionStats
		err          error
	)

	switch event.Name {
	case constnames.ConnectEvent:
		if !event.IsTcp() {
			return
		}
		connectStats, err = a.connectMonitor.ReadInConnectExitSyscall(event)
	case constnames.TcpConnectEvent:
		connectStats, err = a.connectMonitor.ReadInTcpConnect(event)
	case constnames.TcpSetStateEvent:
		connectStats, err = a.connectMonitor.ReadInTcpSetState(event)
	case constnames.WriteEvent:
		fallthrough
	case constnames.WritevEvent:
		fallthrough
	case constnames.SendToEvent:
		fallthrough
	case constnames.SendMsgEvent:
		if filterRequestEvent(event) {
			return
		}
		connectStats, err = a.connectMonitor.ReadSendRequestSyscall(event)
	}

	if err != nil {
		a.telemetry.Logger.Debug("Cannot update connection stats:", zap.Error(err))
		return
	}
	// Connection is not established yet
	if connectStats == nil {
		return
	}

	dataGroup := a.generateDataGroup(connectStats)
	a.passThroughConsumers(dataGroup)
}
