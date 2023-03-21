package tcp_connect_analyzer

import (
	"collector/pkg/analyzer"
	"collector/pkg/consumer"
	"collector/pkg/model"
	"collector/pkg/model/constlabels"
	"github.com/Kindling-project/kindling/collector/pkg/component"
	"github.com/hashicorp/go-multierror"
	"go.uber.org/zap"
)

const (
	TcpConnectMetric analyzer.Type = "tcp_connect_metric_analyzer"
)

type TcpConnectAnalyzer struct {
	config        *Config
	nextConsumers []consumer.Consumer

	eventChannel   chan *model.Event
	connectMonitor *ConnectMonitor

	stopCh chan bool

	telemetry *component.TelemetryTools
}

func New(cfg interface{}, telemetry *component.TelemetryTools, consumers []consumer.Consumer) analyzer.Analyzer {
	config := cfg.(*Config)
	ret := &TcpConnectAnalyzer{
		config:         config,
		nextConsumers:  consumers,
		telemetry:      telemetry,
		eventChannel:   make(chan *model.Event, config.ChannelSize),
		stopCh:         make(chan bool),
		connectMonitor: NewConnectMonitor(telemetry.GetZapLogger()),
	}
	return ret
}

// 分析器所能够消费的事件
func (a *TcpConnectAnalyzer) ConsumableEvents() []string {
	return []string{
		model.ConnectEvent,
		model.TcpConnectEvent,
		model.TcpSetStateEvent,
		model.WriteEvent,
		model.WritevEvent,
		model.SendMsgEvent,
		model.SendToEvent,
	}
}

// Start initializes the analyzer
func (a *TcpConnectAnalyzer) Start() error {
	go func() {
		for {
			select {
			case event := <-a.eventChannel:
				a.consumeChannelEvent(event)
			case <-a.stopCh:
				// Only trim the connections expired. For those unfinished, we leave them
				// unchanged and just shutdown this goroutine.
				//a.trimConnectionsWithTcpStat()
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
		connectStats *ConnectionStats
		err          error
	)

	switch event.Name {
	case model.ConnectEvent:
		if !event.IsTcp() {
			return
		}
		connectStats, err = a.connectMonitor.ReadInConnectExitSyscall(event)
	case model.TcpConnectEvent:
		connectStats, err = a.connectMonitor.ReadInTcpConnect(event)
	case model.TcpSetStateEvent:
		//connectStats, err = a.connectMonitor.ReadInTcpSetState(event)
	case model.WriteEvent:
		fallthrough
	case model.WritevEvent:
		fallthrough
	case model.SendToEvent:
		fallthrough
	case model.SendMsgEvent:
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

func (a *TcpConnectAnalyzer) passThroughConsumers(dataGroup *model.DataGroup) {
	var retError error
	for _, nextConsumer := range a.nextConsumers {
		err := nextConsumer.Consume(dataGroup)
		if err != nil {
			retError = multierror.Append(retError, err)
		}
	}
	if retError != nil {
		a.telemetry.Logger.Warn("Error happened while passing through processors:", zap.Error(retError))
	}
}

func (a *TcpConnectAnalyzer) generateDataGroup(connectStats *ConnectionStats) *model.DataGroup {
	labels := a.generateLabels(connectStats)
	metrics := make([]*model.Metric, 0, 2)
	metrics = append(metrics, model.NewIntMetric(model.TcpConnectTotalMetric, 1))
	// Only record the connection's duration when it is successfully established
	if connectStats.StateMachine.GetCurrentState() == Success {
		metrics = append(metrics, model.NewIntMetric(model.TcpConnectDurationMetric, connectStats.GetConnectDuration()))
	}

	retDataGroup := model.NewDataGroup(
		model.TcpConnectMetricGroupName,
		labels,
		connectStats.EndTimestamp,
		metrics...)

	return retDataGroup
}

// 生成对应的属性标签
func (a *TcpConnectAnalyzer) generateLabels(connectStats *ConnectionStats) *model.AttributeMap {
	labels := model.NewAttributeMap()
	// The connect events always come from the client-side
	labels.AddBoolValue(constlabels.IsServer, false)
	if a.config.NeedProcessInfo {
		labels.AddIntValue(constlabels.Pid, int64(connectStats.Pid))
		labels.AddStringValue(constlabels.Comm, connectStats.Comm)
	}
	labels.AddStringValue(constlabels.ContainerId, connectStats.ContainerId)
	labels.AddIntValue(constlabels.Errno, int64(connectStats.Code))
	if connectStats.StateMachine.GetCurrentState() == Success {
		labels.AddBoolValue(constlabels.Success, true)
	} else {
		labels.AddBoolValue(constlabels.Success, false)
	}

	srcIp := connectStats.ConnKey.SrcIP
	dstIp := connectStats.ConnKey.DstIP
	srcPort := connectStats.ConnKey.SrcPort
	dstPort := connectStats.ConnKey.DstPort
	labels.UpdateAddStringValue(constlabels.SrcIp, srcIp)
	labels.UpdateAddStringValue(constlabels.DstIp, dstIp)
	labels.UpdateAddIntValue(constlabels.SrcPort, int64(srcPort))
	labels.UpdateAddIntValue(constlabels.DstPort, int64(dstPort))
	return labels
}

// 过滤掉对应的类型和协议
func filterRequestEvent(event *model.Event) bool {
	if event.Category != model.Category_CAT_NET {
		return true
	}

	ctx := event.GetCtx()
	if ctx == nil || ctx.GetThreadInfo() == nil {
		return true
	}
	fd := ctx.GetFdInfo()
	if fd == nil {
		return true
	}
	if fd.GetProtocol() != model.L4Proto_TCP {
		return true
	}
	if fd.GetSip() == nil || fd.GetDip() == nil {
		return true
	}

	return false
}

// Shutdown cleans all the resources used by the analyzer
func (a *TcpConnectAnalyzer) Shutdown() error {
	a.stopCh <- true
	return nil
}

// Type returns the type of the analyzer
func (a *TcpConnectAnalyzer) Type() analyzer.Type {
	return TcpConnectMetric
}
