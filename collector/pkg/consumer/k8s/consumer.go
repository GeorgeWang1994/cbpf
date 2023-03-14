package k8s

import (
	"collector/pkg/consumer"
	"github.com/Kindling-project/kindling/collector/pkg/component"
)

type K8sMetadataProcessor struct {
	metadata      *K8sMetaDataCache
	nextConsumer  consumer.Consumer
	localNodeIp   string
	localNodeName string
	telemetry     *component.TelemetryTools
}
