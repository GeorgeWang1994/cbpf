package k8s

// k8s容器信息
type K8sContainerInfo struct {
	// 容器id
	ContainerId string
	// 容器名称
	Name string
	// 记录映射出去的主机端口和容器端口的关系
	HostPortMap map[int32]int32
	// 关联pod信息
	RefPodInfo *K8sPodInfo
}

// k8s pod 信息
type K8sPodInfo struct {
	// ip地址
	Ip string
	// pod名称
	PodName string
	// pod端口列表
	Ports []int32
	// 映射的主机端口列表
	HostPorts []int32
	// 容器id列表
	ContainerIds []string
	// 标签
	Labels map[string]string
	// TODO: There may be multiple kinds of workload or services for the same pod
	WorkloadKind string
	WorkloadName string
	// k8s中的namespace
	Namespace string
	// node名称
	NodeName string
	// node地址
	NodeAddress string
	// 网络是否连接主机
	isHostNetwork bool
	// 关联service信息
	ServiceInfo *K8sServiceInfo
}

// k8s 服务信息
type K8sServiceInfo struct {
	// ip地址
	Ip string
	// 服务名称
	ServiceName string
	// k8s中的namespace
	Namespace string
	// ？
	isNodePort bool
	// ？
	Selector map[string]string
	// TODO: How to delete the workload info when it is deleted?
	WorkloadKind string
	WorkloadName string
}
