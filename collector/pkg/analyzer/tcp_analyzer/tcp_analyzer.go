package tcp_analyzer

import (
	"collector/pkg/analyzer"
	"collector/pkg/consumer"
	"collector/pkg/model"
	"fmt"
	"github.com/Kindling-project/kindling/collector/pkg/component"
	"github.com/Kindling-project/kindling/collector/pkg/model/constlabels"
	"github.com/Kindling-project/kindling/collector/pkg/model/constnames"
	"github.com/hashicorp/go-multierror"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	TcpMetric analyzer.Type = "tcp_metric_analyzer"
)

type TcpMetricAnalyzer struct {
	consumers []consumer.Consumer
	telemetry *component.TelemetryTools
}

func NewTcpMetricAnalyzer(cfg interface{}, telemetry *component.TelemetryTools, nextConsumers []consumer.Consumer) analyzer.Analyzer {
	retAnalyzer := &TcpMetricAnalyzer{
		consumers: nextConsumers,
		telemetry: telemetry,
	}
	return retAnalyzer
}

func (a *TcpMetricAnalyzer) Start() error {
	return nil
}

func (a *TcpMetricAnalyzer) ConsumableEvents() []string {
	return []string{
		model.TcpCloseEvent,
		model.TcpRcvEstablishedEvent,
		model.TcpDropEvent,
		model.TcpRetransmitSkbEvent,
	}
}

func (a *TcpMetricAnalyzer) ConsumeEvent(event *model.Event) error {
	var dataGroup *model.DataGroup
	var err error
	switch event.Name {
	case model.TcpCloseEvent:
		fallthrough
	case model.TcpRcvEstablishedEvent:
		dataGroup, err = a.generateRtt(event)
	case model.TcpDropEvent:
		dataGroup, err = a.generateDrop(event)
	case model.TcpRetransmitSkbEvent:
		dataGroup, err = a.generateRetransmit(event)
	default:
		return nil
	}
	if err != nil {
		if ce := a.telemetry.Logger.Check(zapcore.DebugLevel, "Event Skip, "); ce != nil {
			ce.Write(
				zap.Error(err),
			)
		}
		return nil
	}
	if dataGroup == nil {
		return nil
	}
	var retError error
	for _, nextConsumer := range a.consumers {
		err := nextConsumer.Consume(dataGroup)
		if err != nil {
			retError = multierror.Append(retError, err)
		}
	}
	return retError
}

func (a *TcpMetricAnalyzer) generateRtt(event *model.Event) (*model.DataGroup, error) {
	// Only client-side has rtt metric
	labels, err := a.getTupleLabels(event)
	if err != nil {
		return nil, err
	}
	// Unit is microsecond
	rtt := event.GetUintUserAttribute("rtt")
	// rtt is zero when the kprobe is invoked in the first time, which should be filtered
	if rtt == 0 {
		return nil, nil
	}
	metric := model.NewIntMetric(constnames.TcpRttMetricName, int64(rtt))
	return model.NewDataGroup(model.TcpMetricGroupName, labels, event.Timestamp, metric), nil
}

func (a *TcpMetricAnalyzer) generateRetransmit(event *model.Event) (*model.DataGroup, error) {
	labels, err := a.getTupleLabels(event)
	if err != nil {
		return nil, err
	}
	metric := model.NewIntMetric(constnames.TcpRetransmitMetricName, 1)
	return model.NewDataGroup(model.TcpMetricGroupName, labels, event.Timestamp, metric), nil
}

func (a *TcpMetricAnalyzer) generateDrop(event *model.Event) (*model.DataGroup, error) {
	labels, err := a.getTupleLabels(event)
	if err != nil {
		return nil, err
	}
	metric := model.NewIntMetric(constnames.TcpDropMetricName, 1)
	return model.NewDataGroup(model.TcpMetricGroupName, labels, event.Timestamp, metric), nil
}

func (a *TcpMetricAnalyzer) getTupleLabels(event *model.Event) (*model.AttributeMap, error) {
	// Note: Here sIp/dIp doesn't mean IP from client/server side for sure.
	// sIp stands for the IP which sends tcp flow.
	sIp := event.GetUserAttribute("sip")
	sPort := event.GetUserAttribute("sport")
	dIp := event.GetUserAttribute("dip")
	dPort := event.GetUserAttribute("dport")

	if sIp == nil || sPort == nil || dIp == nil || dPort == nil {
		return nil, fmt.Errorf("one of sip or dip or dport is nil for event %s", event.Name)
	}
	sIpString := model.IPLong2String(uint32(sIp.GetUintValue()))
	sPortUint := sPort.GetUintValue()
	dIpString := model.IPLong2String(uint32(dIp.GetUintValue()))
	dPortUint := dPort.GetUintValue()

	labels := model.NewAttributeMap()
	labels.AddStringValue(constlabels.SrcIp, sIpString)
	labels.AddIntValue(constlabels.SrcPort, int64(sPortUint))
	labels.AddStringValue(constlabels.DstIp, dIpString)
	labels.AddIntValue(constlabels.DstPort, int64(dPortUint))

	return labels, nil
}

func (a *TcpMetricAnalyzer) Shutdown() error {
	return nil
}

func (a *TcpMetricAnalyzer) Type() analyzer.Type {
	return TcpMetric
}
