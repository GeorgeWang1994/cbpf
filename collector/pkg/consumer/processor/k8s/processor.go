package k8s

import (
	"collector/pkg/consumer"
	"collector/pkg/consumer/processor"
	"collector/pkg/model"
	"github.com/Kindling-project/kindling/collector/pkg/component"
	"github.com/Kindling-project/kindling/collector/pkg/model/constlabels"
	"go.uber.org/zap"
	"strconv"
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
	isServer := dataGroup.Labels.GetBoolValue(constlabels.IsServer)
	if isServer {
		p.addK8sMetaDataForServerLabel(dataGroup.Labels)
	} else {
		p.addK8sMetaDataForClientLabel(dataGroup.Labels)
	}
}

// 为来源端增加k8s数据标签，其中的标签都来自于network_analyzer打上
func (p *K8sMetadataProcessor) addK8sMetaDataForClientLabel(labelMap *model.AttributeMap) {
	// add metadata for src
	containerId := labelMap.GetStringValue(constlabels.ContainerId)
	if containerId != "" {
		labelMap.UpdateAddStringValue(constlabels.SrcContainerId, containerId)
		resInfo, ok := p.metadata.GetByContainerId(containerId)
		if ok {
			addContainerMetaInfoLabelSRC(labelMap, resInfo)
		} else {
			labelMap.UpdateAddStringValue(constlabels.SrcNodeIp, p.localNodeIp)
			labelMap.UpdateAddStringValue(constlabels.SrcNode, p.localNodeName)
			labelMap.UpdateAddStringValue(constlabels.SrcNamespace, constlabels.InternalClusterNamespace)
		}
	} else {
		srcIp := labelMap.GetStringValue(constlabels.SrcIp)
		if srcIp == loopbackIp {
			labelMap.UpdateAddStringValue(constlabels.SrcNodeIp, p.localNodeIp)
			labelMap.UpdateAddStringValue(constlabels.SrcNode, p.localNodeName)
		}
		podInfo, ok := p.metadata.GetPodByIp(srcIp)
		if ok {
			addPodMetaInfoLabelSRC(labelMap, podInfo)
		} else {
			if nodeName, ok := p.metadata.GetNodeNameByIp(srcIp); ok {
				labelMap.UpdateAddStringValue(constlabels.SrcNodeIp, srcIp)
				labelMap.UpdateAddStringValue(constlabels.SrcNode, nodeName)
				labelMap.UpdateAddStringValue(constlabels.SrcNamespace, constlabels.InternalClusterNamespace)
			} else {
				labelMap.UpdateAddStringValue(constlabels.SrcNamespace, constlabels.ExternalClusterNamespace)
			}
		}
	}

	// add metadata for dst
	dstIp := labelMap.GetStringValue(constlabels.DstIp)
	if dstIp == loopbackIp {
		labelMap.UpdateAddStringValue(constlabels.DstNodeIp, p.localNodeIp)
		labelMap.UpdateAddStringValue(constlabels.DstNode, p.localNodeName)
		// If the dst IP is a loopback address, we use its src IP for further searching.
		dstIp = labelMap.GetStringValue(constlabels.SrcIp)
	}
	dstPort := labelMap.GetIntValue(constlabels.DstPort)
	// DstIp is IP of a service
	if svcInfo, ok := p.metadata.GetServiceByIpPort(dstIp, uint32(dstPort)); ok {
		labelMap.UpdateAddStringValue(constlabels.DstNamespace, svcInfo.Namespace)
		labelMap.UpdateAddStringValue(constlabels.DstService, svcInfo.ServiceName)
		labelMap.UpdateAddStringValue(constlabels.DstWorkloadKind, svcInfo.WorkloadKind)
		labelMap.UpdateAddStringValue(constlabels.DstWorkloadName, svcInfo.WorkloadName)
		// find podInfo using dnat_ip
		dNatIp := labelMap.GetStringValue(constlabels.DnatIp)
		dNatPort := labelMap.GetIntValue(constlabels.DnatPort)
		if dNatIp != "" && dNatPort != -1 {
			resInfo, ok := p.metadata.GetContainerByIpPort(dNatIp, uint32(dNatPort))
			if ok {
				addContainerMetaInfoLabelDST(labelMap, resInfo)
			} else {
				// maybe dnat_ip is NodeIP
				if nodeName, ok := p.metadata.GetNodeNameByIp(dNatIp); ok {
					labelMap.UpdateAddStringValue(constlabels.DstNodeIp, dNatIp)
					labelMap.UpdateAddStringValue(constlabels.DstNode, nodeName)
				}
			}
		}
	} else if resInfo, ok := p.metadata.GetContainerByIpPort(dstIp, uint32(dstPort)); ok {
		// DstIp is IP of a container
		addContainerMetaInfoLabelDST(labelMap, resInfo)
	} else if resInfo, ok := p.metadata.GetContainerByHostIpPort(dstIp, uint32(dstPort)); ok {
		addContainerMetaInfoLabelDST(labelMap, resInfo)
		labelMap.UpdateAddStringValue(constlabels.DstIp, resInfo.RefPodInfo.Ip)
		labelMap.UpdateAddIntValue(constlabels.DstPort, int64(resInfo.HostPortMap[int32(dstPort)]))
		labelMap.UpdateAddStringValue(constlabels.DstService, dstIp+":"+strconv.Itoa(int(dstPort)))
	} else {
		// DstIp is a IP from external
		if nodeName, ok := p.metadata.GetNodeNameByIp(dstIp); ok {
			labelMap.UpdateAddStringValue(constlabels.DstNodeIp, dstIp)
			labelMap.UpdateAddStringValue(constlabels.DstNode, nodeName)
			labelMap.UpdateAddStringValue(constlabels.DstNamespace, constlabels.InternalClusterNamespace)
		} else {
			labelMap.UpdateAddStringValue(constlabels.DstNamespace, constlabels.ExternalClusterNamespace)
		}
	}
}

// 为目的端增加k8s数据标签
func (p *K8sMetadataProcessor) addK8sMetaDataForServerLabel(labelMap *model.AttributeMap) {
	srcIp := labelMap.GetStringValue(constlabels.SrcIp)
	if srcIp == loopbackIp {
		labelMap.UpdateAddStringValue(constlabels.SrcNodeIp, p.localNodeIp)
		labelMap.UpdateAddStringValue(constlabels.SrcNode, p.localNodeName)
	}
	podInfo, ok := p.metadata.GetPodByIp(srcIp)
	if ok {
		addPodMetaInfoLabelSRC(labelMap, podInfo)
	} else {
		if nodeName, ok := p.metadata.GetNodeNameByIp(srcIp); ok {
			labelMap.UpdateAddStringValue(constlabels.SrcNodeIp, srcIp)
			labelMap.UpdateAddStringValue(constlabels.SrcNode, nodeName)
			labelMap.UpdateAddStringValue(constlabels.SrcNamespace, constlabels.InternalClusterNamespace)
		} else {
			labelMap.UpdateAddStringValue(constlabels.SrcNamespace, constlabels.ExternalClusterNamespace)
		}
	}
	containerId := labelMap.GetStringValue(constlabels.ContainerId)
	labelMap.UpdateAddStringValue(constlabels.DstContainerId, containerId)
	containerInfo, ok := p.metadata.GetByContainerId(containerId)
	if ok {
		addContainerMetaInfoLabelDST(labelMap, containerInfo)
		if containerInfo.RefPodInfo.ServiceInfo != nil {
			labelMap.UpdateAddStringValue(constlabels.DstService, containerInfo.RefPodInfo.ServiceInfo.ServiceName)
		}
	} else {
		labelMap.UpdateAddStringValue(constlabels.DstNodeIp, p.localNodeIp)
		labelMap.UpdateAddStringValue(constlabels.DstNode, p.localNodeName)
		labelMap.UpdateAddStringValue(constlabels.DstNamespace, constlabels.InternalClusterNamespace)
	}
}

func (p *K8sMetadataProcessor) processTcpMetric(dataGroup *model.DataGroup) {
	p.addK8sMetaDataViaIp(dataGroup.Labels)
}

// addK8sMetaDataViaIp is used to add k8s metadata to tcp metrics.
// There is also a piece of code for removing "port" in this method, which
// should be moved into a processor that is used for relabeling tcp metrics later.
// 通过ip地址和端口获取k8s数据并且加入到指标中
func (p *K8sMetadataProcessor) addK8sMetaDataViaIp(labelMap *model.AttributeMap) {
	// Both Src and Dst should try:
	// 1. (Only Dst)Use Ip Port to find Service (when found a Service,also use DNatIp to find the Pod)
	// 2. Use Ip Port to find Container And Pod
	// 3. Use Ip to find Pod

	// add metadata for src
	p.addK8sMetaDataViaIpSRC(labelMap)
	// add metadata for dst
	p.addK8sMetaDataViaIpDST(labelMap)

	// We only care about the real connection, so here replace DstIp/DstPort with DNatIp/DNatPort
	// 如果能获取到dnat中的数据，则替换
	if labelMap.GetStringValue(constlabels.DnatIp) != "" {
		labelMap.AddStringValue(constlabels.DstIp, labelMap.GetStringValue(constlabels.DnatIp))
	}
	if labelMap.GetIntValue(constlabels.DnatPort) > 0 {
		labelMap.AddIntValue(constlabels.DstPort, labelMap.GetIntValue(constlabels.DnatPort))
	}
	labelMap.RemoveAttribute(constlabels.DnatIp)
	labelMap.RemoveAttribute(constlabels.DnatPort)
	// Metric shouldn't contain high-cardinality labels, so here we want to remove
	// the dynamic port label and retain the listening one. But we can't know which
	// port is dynamic for sure, so we work around that by comparing their number size.
	//
	// The default dynamic port range in /proc/sys/net/ipv4/ip_local_port_range is 32768~60999.
	// At most cases, the larger port is the dynamic port and the other one is the listening port.
	// But sometimes the listening port is also greater than 32768 in which case there is no way to
	// tell which one is listening.
	/**
	指标不应该包含高基数标签，所以这里我们希望删除动态端口标签并保留侦听端口标签。
	但我们不能确定哪个端口是动态的，所以我们通过比较它们的数字大小来解决这个问题。
	/proc/sys/net/ipv4/ip_local_port_range中的默认动态端口范围是32768~6099。
	在大多数情况下，较大的端口是动态端口，另一个是侦听端口。
	但有时监听端口也大于32768，在这种情况下，无法判断哪一个正在监听
	*/
	var defaultMinLocalPort int64 = 32768
	srcPort := labelMap.GetIntValue(constlabels.SrcPort)
	dstPort := labelMap.GetIntValue(constlabels.DstPort)
	// If they are both smaller than 32768 then we remove the much smaller one.
	if srcPort < defaultMinLocalPort && dstPort < defaultMinLocalPort {
		if srcPort > dstPort {
			labelMap.RemoveAttribute(constlabels.SrcPort)
		} else {
			labelMap.RemoveAttribute(constlabels.DstPort)
		}
	} else {
		// Otherwise, we remove the port that is larger than 32768.
		if srcPort >= defaultMinLocalPort {
			labelMap.RemoveAttribute(constlabels.SrcPort)
		}
		if dstPort >= defaultMinLocalPort {
			labelMap.RemoveAttribute(constlabels.DstPort)
		}
	}
}

// 通过来源ip地址和端口获取到k8s meta信息
func (p *K8sMetadataProcessor) addK8sMetaDataViaIpSRC(labelMap *model.AttributeMap) {
	// 1. Use Ip Port to find Container And Pod
	// 2. Use Ip to find Pod
	srcIp := labelMap.GetStringValue(constlabels.SrcIp)
	srcPort := labelMap.GetIntValue(constlabels.SrcPort)
	// 根据ip地址获取到容器信息
	srcContainerInfo, ok := p.metadata.GetContainerByIpPort(srcIp, uint32(srcPort))
	if ok {
		addContainerMetaInfoLabelSRC(labelMap, srcContainerInfo)
		return
	}

	// 根据ip地址获取到pod信息
	srcPodInfo, ok := p.metadata.GetPodByIp(srcIp)
	if ok {
		addPodMetaInfoLabelSRC(labelMap, srcPodInfo)
		return
	}
	if _, ok := p.metadata.GetNodeNameByIp(srcIp); ok {
		labelMap.UpdateAddStringValue(constlabels.SrcNamespace, constlabels.InternalClusterNamespace)
	} else {
		labelMap.UpdateAddStringValue(constlabels.SrcNamespace, constlabels.ExternalClusterNamespace)
	}
}

// 通过目的ip地址和端口获取到k8s meta信息
func (p *K8sMetadataProcessor) addK8sMetaDataViaIpDST(labelMap *model.AttributeMap) {
	// 1. (Only Dst)Use Ip Port to find Service (when found a Service,also use DNatIp to find the Pod)
	// 2. Use Ip Port to find Container And Pod
	// 3. Use Ip to find Pod
	dstIp := labelMap.GetStringValue(constlabels.DstIp)
	dstPort := labelMap.GetIntValue(constlabels.DstPort)
	dstSvcInfo, ok := p.metadata.GetServiceByIpPort(dstIp, uint32(dstPort))
	if ok {
		labelMap.UpdateAddStringValue(constlabels.DstNamespace, dstSvcInfo.Namespace)
		labelMap.UpdateAddStringValue(constlabels.DstService, dstSvcInfo.ServiceName)
		labelMap.UpdateAddStringValue(constlabels.DstWorkloadKind, dstSvcInfo.WorkloadKind)
		labelMap.UpdateAddStringValue(constlabels.DstWorkloadName, dstSvcInfo.WorkloadName)
		// find podInfo using dnat_ip
		dNatIp := labelMap.GetStringValue(constlabels.DnatIp)
		dNatPort := labelMap.GetIntValue(constlabels.DnatPort)
		if dNatIp != "" && dNatPort != -1 {
			resInfo, ok := p.metadata.GetContainerByIpPort(dNatIp, uint32(dNatPort))
			if ok {
				addContainerMetaInfoLabelDST(labelMap, resInfo)
			}
		}
		return
	}

	// 根据ip地址获取容器信息后保存到map中
	dstContainerInfo, ok := p.metadata.GetContainerByIpPort(dstIp, uint32(dstPort))
	if ok {
		addContainerMetaInfoLabelDST(labelMap, dstContainerInfo)
		return
	}

	// 根据主机ip地址获取容器信息后保存到map中
	dstContainerInfo, ok = p.metadata.GetContainerByHostIpPort(dstIp, uint32(dstPort))
	if ok {
		addContainerMetaInfoLabelDST(labelMap, dstContainerInfo)
		labelMap.UpdateAddStringValue(constlabels.DstIp, dstContainerInfo.RefPodInfo.Ip)
		labelMap.UpdateAddIntValue(constlabels.DstPort, int64(dstContainerInfo.HostPortMap[int32(dstPort)]))
		labelMap.UpdateAddStringValue(constlabels.DstService, dstIp+":"+strconv.Itoa(int(dstPort)))
	}

	// 根据ip地址获取到pod信息后保存到map中
	dstPodInfo, ok := p.metadata.GetPodByIp(dstIp)
	if ok {
		addPodMetaInfoLabelDST(labelMap, dstPodInfo)
		return
	}
	if _, ok := p.metadata.GetNodeNameByIp(dstIp); ok {
		labelMap.UpdateAddStringValue(constlabels.DstNamespace, constlabels.InternalClusterNamespace)
	} else {
		labelMap.UpdateAddStringValue(constlabels.DstNamespace, constlabels.ExternalClusterNamespace)
	}
}

// 添加来源容器信息
func addContainerMetaInfoLabelSRC(labelMap *model.AttributeMap, containerInfo *K8sContainerInfo) {
	labelMap.UpdateAddStringValue(constlabels.SrcContainer, containerInfo.Name)
	labelMap.UpdateAddStringValue(constlabels.SrcContainerId, containerInfo.ContainerId)
	addPodMetaInfoLabelSRC(labelMap, containerInfo.RefPodInfo)
}

// 添加来源pod信息
func addPodMetaInfoLabelSRC(labelMap *model.AttributeMap, podInfo *K8sPodInfo) {
	labelMap.UpdateAddStringValue(constlabels.SrcNode, podInfo.NodeName)
	labelMap.UpdateAddStringValue(constlabels.SrcNodeIp, podInfo.NodeAddress)
	labelMap.UpdateAddStringValue(constlabels.SrcNamespace, podInfo.Namespace)
	labelMap.UpdateAddStringValue(constlabels.SrcWorkloadKind, podInfo.WorkloadKind)
	labelMap.UpdateAddStringValue(constlabels.SrcWorkloadName, podInfo.WorkloadName)
	labelMap.UpdateAddStringValue(constlabels.SrcPod, podInfo.PodName)
	labelMap.UpdateAddStringValue(constlabels.SrcIp, podInfo.Ip)
	if podInfo.ServiceInfo != nil {
		labelMap.UpdateAddStringValue(constlabels.SrcService, podInfo.ServiceInfo.ServiceName)
	}
}

// 添加目的容器信息
func addContainerMetaInfoLabelDST(labelMap *model.AttributeMap, containerInfo *K8sContainerInfo) {
	labelMap.UpdateAddStringValue(constlabels.DstContainer, containerInfo.Name)
	labelMap.UpdateAddStringValue(constlabels.DstContainerId, containerInfo.ContainerId)
	addPodMetaInfoLabelDST(labelMap, containerInfo.RefPodInfo)
}

// 添加目的Pod信息
func addPodMetaInfoLabelDST(labelMap *model.AttributeMap, podInfo *K8sPodInfo) {
	labelMap.UpdateAddStringValue(constlabels.DstNode, podInfo.NodeName)
	labelMap.UpdateAddStringValue(constlabels.DstNodeIp, podInfo.NodeAddress)
	labelMap.UpdateAddStringValue(constlabels.DstNamespace, podInfo.Namespace)
	labelMap.UpdateAddStringValue(constlabels.DstWorkloadKind, podInfo.WorkloadKind)
	labelMap.UpdateAddStringValue(constlabels.DstWorkloadName, podInfo.WorkloadName)
	labelMap.UpdateAddStringValue(constlabels.DstPod, podInfo.PodName)
	if labelMap.GetStringValue(constlabels.DstIp) == "" {
		labelMap.UpdateAddStringValue(constlabels.DstIp, podInfo.Ip)
	}
}
