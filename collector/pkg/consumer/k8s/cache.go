package k8s

import "sync"

type K8sMetaDataCache struct {
	// 容器id和容器之间的映射
	cMut            sync.RWMutex
	containerIdInfo map[string]*K8sContainerInfo
	//
	//    "192.168.1.14": { // podIp
	//        9093: k8sResInfo,
	//        6783: k8sResInfo
	//    },
	//    "192.168.2.15": { // podIp
	//        0: k8sResInfo,
	//        6783: k8sResInfo
	//    },
	//    "10.1.11.213": { // serviceIp
	//        8080: k8sResInfo
	//    }
	//}
	// pod ip地址和容器之间的映射
	pMut            sync.RWMutex
	ipContainerInfo map[string]map[uint32]*K8sContainerInfo
	// pod ip地址和服务之间的映射
	sMut          sync.RWMutex
	ipServiceInfo map[string]map[uint32]*K8sServiceInfo
	// 主机地址端口和容器之间的映射
	hostPortInfo *HostPortMap
}

func NewCache() *K8sMetaDataCache {
	c := &K8sMetaDataCache{
		containerIdInfo: make(map[string]*K8sContainerInfo),
		ipContainerInfo: make(map[string]map[uint32]*K8sContainerInfo),
		ipServiceInfo:   make(map[string]map[uint32]*K8sServiceInfo),
		hostPortInfo:    newHostPortMap(),
	}

	return c
}
