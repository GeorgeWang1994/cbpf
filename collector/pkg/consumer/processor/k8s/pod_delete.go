package k8s

import (
	"sync"
	"time"
)

var (
	podDeleteQueueMut sync.Mutex
	podDeleteQueue    []deleteRequest
)

type deleteRequest struct {
	podInfo *deletedPodInfo
	ts      time.Time
}

type deletedPodInfo struct {
	name         string
	namespace    string
	containerIds []string
	ip           string
	ports        []int32
	hostIp       string
	hostPorts    []int32
}

// deleteLoop deletes pods from cache periodically.
func podDeleteLoop(interval time.Duration, gracePeriod time.Duration, stopCh chan struct{}) {
	// This loop runs after N seconds and deletes pods from cache.
	// It iterates over the delete queue and deletes all that aren't
	// in the grace period anymore.
	for {
		select {
		case <-time.After(interval):
			var cutoff int
			now := time.Now()
			podDeleteQueueMut.Lock()
			// 检查时间是否超出设定的时间
			for i, d := range podDeleteQueue {
				if d.ts.Add(gracePeriod).After(now) {
					break
				}
				cutoff = i + 1
			}
			toDelete := podDeleteQueue[:cutoff]
			podDeleteQueue = podDeleteQueue[cutoff:]
			podDeleteQueueMut.Unlock()
			for _, d := range toDelete {
				deletePodInfo(d.podInfo)
			}

		case <-stopCh:
			return
		}
	}
}

// 删除pod信息
func deletePodInfo(podInfo *deletedPodInfo) {
	if podInfo.name != "" {
		GlobalPodInfo.delete(podInfo.namespace, podInfo.name)
	}
	// 根据容器id来删除信息
	if len(podInfo.containerIds) != 0 {
		for i := 0; i < len(podInfo.containerIds); i++ {
			MetaDataCache.DeleteByContainerId(podInfo.containerIds[i])
		}
	}
	// 根据访问端口来删除容器信息
	if podInfo.ip != "" && len(podInfo.ports) != 0 {
		for _, port := range podInfo.ports {
			// Assume that PodIP:Port can't be reused in a few seconds
			MetaDataCache.DeleteContainerByIpPort(podInfo.ip, uint32(port))
		}
	}
	// 根据主机端口删除容器信息
	if podInfo.hostIp != "" && len(podInfo.hostPorts) != 0 {
		for _, port := range podInfo.hostPorts {
			MetaDataCache.DeleteContainerByHostIpPort(podInfo.hostIp, uint32(port))
		}
	}
}
