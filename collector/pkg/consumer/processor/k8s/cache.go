package k8s

import (
	"encoding/json"
	"fmt"
	"sync"
)

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

// 添加容器id对应的容器信息
func (c *K8sMetaDataCache) AddByContainerId(containerId string, resource *K8sContainerInfo) {
	c.cMut.Lock()
	c.containerIdInfo[containerId] = resource
	c.cMut.Unlock()
}

// 根据容器id获取容器信息
func (c *K8sMetaDataCache) GetByContainerId(containerId string) (*K8sContainerInfo, bool) {
	c.cMut.RLock()
	res, ok := c.containerIdInfo[containerId]
	c.cMut.RUnlock()
	if ok {
		return res, ok
	}
	return nil, false
}

// 根据容器id获取pod信息
func (c *K8sMetaDataCache) GetPodByContainerId(containerId string) (*K8sPodInfo, bool) {
	c.cMut.RLock()
	containerInfo, ok := c.containerIdInfo[containerId]
	c.cMut.RUnlock()
	if ok {
		return containerInfo.RefPodInfo, ok
	}
	return nil, false
}

// 根据容器id删除
func (c *K8sMetaDataCache) DeleteByContainerId(containerId string) {
	c.cMut.Lock()
	delete(c.containerIdInfo, containerId)
	c.cMut.Unlock()
}

// 添加
func (c *K8sMetaDataCache) AddContainerByIpPort(ip string, port uint32, resource *K8sContainerInfo) {
	c.pMut.RLock()
	portContainerInfo, ok := c.ipContainerInfo[ip]
	c.pMut.RUnlock()
	if ok {
		c.pMut.Lock()
		portContainerInfo[port] = resource
		c.pMut.Unlock()
	} else {
		portContainerInfo = make(map[uint32]*K8sContainerInfo)
		portContainerInfo[port] = resource
		c.pMut.Lock()
		c.ipContainerInfo[ip] = portContainerInfo
		c.pMut.Unlock()
	}
}

// 通过ip和端口获取容器信息
func (c *K8sMetaDataCache) GetContainerByIpPort(ip string, port uint32) (*K8sContainerInfo, bool) {
	c.pMut.RLock()
	portContainerInfo, ok := c.ipContainerInfo[ip]
	defer c.pMut.RUnlock()
	if !ok {
		return nil, false
	}
	containerInfo, ok := portContainerInfo[port]
	if ok {
		return containerInfo, true
	}
	// maybe such pod has a port which is not declared explicitly
	containerInfo, ok = portContainerInfo[0]
	if !ok {
		// find the first pod whose network mode is not hostnetwork
		for _, info := range portContainerInfo {
			if !info.RefPodInfo.isHostNetwork && info.RefPodInfo.WorkloadKind != "daemonset" {
				return info, true
			}
		}
		return nil, false
	} else {
		if !containerInfo.RefPodInfo.isHostNetwork && containerInfo.RefPodInfo.WorkloadKind != "daemonset" {
			return containerInfo, true
		}
		return nil, false
	}
}

// 根据ip和端口获取Pod信息
func (c *K8sMetaDataCache) GetPodByIpPort(ip string, port uint32) (*K8sPodInfo, bool) {
	containerInfo, ok := c.GetContainerByIpPort(ip, port)
	if !ok {
		return nil, false
	}
	return containerInfo.RefPodInfo, true
}

// 根据ip地址获取pod信息
func (c *K8sMetaDataCache) GetPodByIp(ip string) (*K8sPodInfo, bool) {
	c.pMut.RLock()
	portContainerInfo, ok := c.ipContainerInfo[ip]
	defer c.pMut.RUnlock()
	if !ok {
		return nil, false
	}
	// find the first pod whose network mode is not hostnetwork
	for _, info := range portContainerInfo {
		if !info.RefPodInfo.isHostNetwork && info.RefPodInfo.WorkloadKind != "daemonset" {
			return info.RefPodInfo, true
		}
	}
	return nil, false
}

// 根据ip和端口删除容器信息
func (c *K8sMetaDataCache) DeleteContainerByIpPort(ip string, port uint32) {
	c.pMut.RLock()
	portContainerInfo, ok := c.ipContainerInfo[ip]
	c.pMut.RUnlock()
	if !ok {
		return
	}
	c.pMut.Lock()
	delete(portContainerInfo, port)
	if len(portContainerInfo) == 0 {
		delete(c.ipContainerInfo, ip)
	}
	c.pMut.Unlock()
}

// 根据主机ip和端口添加容器信息
func (c *K8sMetaDataCache) AddContainerByHostIpPort(hostIp string, hostPort uint32, containerInfo *K8sContainerInfo) {
	c.hostPortInfo.add(hostIp, hostPort, containerInfo)
}

// 根据主机和端口获取容器信息
func (c *K8sMetaDataCache) GetContainerByHostIpPort(hostIp string, hostPort uint32) (*K8sContainerInfo, bool) {
	return c.hostPortInfo.get(hostIp, hostPort)
}

// 根据主机ip和端口删除容器信息
func (c *K8sMetaDataCache) DeleteContainerByHostIpPort(hostIp string, hostPort uint32) {
	c.hostPortInfo.delete(hostIp, hostPort)
}

// 根据ip和端口添加服务信息
func (c *K8sMetaDataCache) AddServiceByIpPort(ip string, port uint32, resource *K8sServiceInfo) {
	c.sMut.RLock()
	portServiceInfo, ok := c.ipServiceInfo[ip]
	c.sMut.RUnlock()
	if ok {
		c.sMut.Lock()
		portServiceInfo[port] = resource
		c.sMut.Unlock()
	} else {
		portServiceInfo = make(map[uint32]*K8sServiceInfo)
		portServiceInfo[port] = resource
		c.sMut.Lock()
		c.ipServiceInfo[ip] = portServiceInfo
		c.sMut.Unlock()
	}
}

// 根据ip和端口获取服务信息
func (c *K8sMetaDataCache) GetServiceByIpPort(ip string, port uint32) (*K8sServiceInfo, bool) {
	c.sMut.RLock()
	portServiceInfo, ok := c.ipServiceInfo[ip]
	defer c.sMut.RUnlock()
	if !ok {
		return nil, false
	}
	serviceInfo, ok := portServiceInfo[port]
	if ok {
		return serviceInfo, true
	}
	return nil, false
}

// 根据ip和端口删除服务信息
func (c *K8sMetaDataCache) DeleteServiceByIpPort(ip string, port uint32) {
	c.sMut.RLock()
	portServiceInfo, ok := c.ipServiceInfo[ip]
	c.sMut.RUnlock()
	if !ok {
		return
	}
	c.sMut.Lock()
	delete(portServiceInfo, port)
	if len(portServiceInfo) == 0 {
		delete(c.ipServiceInfo, ip)
	}
	c.sMut.Unlock()
}

// 清理全部的缓存
func (c *K8sMetaDataCache) ClearAll() {
	c.pMut.Lock()
	c.ipContainerInfo = make(map[string]map[uint32]*K8sContainerInfo)
	c.pMut.Unlock()

	c.sMut.Lock()
	c.ipServiceInfo = make(map[string]map[uint32]*K8sServiceInfo)
	c.sMut.Unlock()

	c.cMut.Lock()
	c.containerIdInfo = make(map[string]*K8sContainerInfo)
	c.cMut.Unlock()
}

func (c *K8sMetaDataCache) String() string {
	containerIdPodJson, _ := json.Marshal(c.containerIdInfo)
	ipContainerJson, _ := json.Marshal(c.ipContainerInfo)
	ipServiceJson, _ := json.Marshal(c.ipServiceInfo)
	return fmt.Sprintf("{\"containerIdPodInfo\": %s, \"ipContainerInfo\": %s, \"ipServiceInfo\": %s}",
		string(containerIdPodJson), string(ipContainerJson), string(ipServiceJson))
}

// 根据ip获取node名称
func (c *K8sMetaDataCache) GetNodeNameByIp(ip string) (string, bool) {
	return GlobalNodeInfo.GetNodeName(ip)
}
