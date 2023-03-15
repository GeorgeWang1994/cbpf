package k8s

import (
	"collector/pkg/consumer"
	"collector/pkg/consumer/processor"
	"collector/pkg/model"
	"github.com/Kindling-project/kindling/collector/pkg/component"
	"go.uber.org/zap"
)

type K8sMetadataProcessor struct {
	metadata      *K8sMetaDataCache
	nextConsumer  consumer.Consumer
	localNodeIp   string
	localNodeName string
	telemetry     *component.TelemetryTools
}

type Config struct {
	KubeAuthType  AuthType `mapstructure:"kube_auth_type"`
	KubeConfigDir string   `mapstructure:"kube_config_dir"`
	// GraceDeletePeriod controls the delay interval after receiving delete event.
	// The unit is seconds, and the default value is 60 seconds.
	// Should not be lower than 30 seconds.
	GraceDeletePeriod int `mapstructure:"grace_delete_period"`
}

var DefaultConfig Config = Config{
	KubeAuthType:      "serviceAccount",
	KubeConfigDir:     "~/.kube/config",
	GraceDeletePeriod: 60,
}

func NewKubernetesProcessor(cfg interface{}, telemetry *component.TelemetryTools, nextConsumer consumer.Consumer) processor.Processor {
	config, ok := cfg.(*Config)
	if !ok {
		telemetry.Logger.Panic("Cannot convert Component config", zap.String("componentType", K8sMetadata))
	}
	var options []Option
	options = append(options, WithAuthType(config.KubeAuthType))
	options = append(options, WithKubeConfigDir(config.KubeConfigDir))
	options = append(options, WithGraceDeletePeriod(config.GraceDeletePeriod))
	err := InitK8sHandler(options...)
	if err != nil {
		telemetry.GetZapLogger().Sugar().Panicf("Failed to initialize [%s]: %v", K8sMetadata, err)
		return nil
	}

	var localNodeIp, localNodeName string
	if localNodeIp, err = getHostIpFromEnv(); err != nil {
		telemetry.Logger.Warn("Local NodeIp can not found", zap.Error(err))
	}
	if localNodeName, err = getHostNameFromEnv(); err != nil {
		telemetry.Logger.Warn("Local NodeName can not found", zap.Error(err))
	}
	return &K8sMetadataProcessor{
		metadata:      MetaDataCache,
		nextConsumer:  nextConsumer,
		localNodeIp:   localNodeIp,
		localNodeName: localNodeName,
		telemetry:     telemetry,
	}
}

func (p *K8sMetadataProcessor) Consume(dataGroup *model.DataGroup) error {
	name := dataGroup.Name
	// 根据数据的名称调用不同的方法来处理数据
	switch name {
	case model.NetRequestMetricGroupName:
		p.processNetRequestMetric(dataGroup)
	case model.TcpMetricGroupName:
		p.processTcpMetric(dataGroup)
	default:
		p.processNetRequestMetric(dataGroup)
	}
	return p.nextConsumer.Consume(dataGroup)
}

func (p *K8sMetadataProcessor) processNetRequestMetric(dataGroup *model.DataGroup) {

}

func (p *K8sMetadataProcessor) processTcpMetric(dataGroup *model.DataGroup) {

}
