package k8s

import (
	"fmt"
	"github.com/prometheus/common/log"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"sync"
	"time"
)

// 自定义pod map信息
type podMap struct {
	// namespace:
	//   podName: podInfo{}
	// 以namespace作为key，pod名称作为子key的map
	Info  map[string]map[string]*K8sPodInfo
	mutex sync.RWMutex
}

var GlobalPodInfo = newPodMap()

func newPodMap() *podMap {
	return &podMap{
		Info:  make(map[string]map[string]*K8sPodInfo),
		mutex: sync.RWMutex{},
	}
}

func (m *podMap) add(info *K8sPodInfo) {
	m.mutex.Lock()
	podInfoMap, ok := m.Info[info.Namespace]
	if !ok {
		podInfoMap = make(map[string]*K8sPodInfo)
	}
	podInfoMap[info.PodName] = info
	m.Info[info.Namespace] = podInfoMap
	m.mutex.Unlock()
}

func (m *podMap) delete(namespace string, name string) {
	m.mutex.Lock()
	podInfoMap, ok := m.Info[namespace]
	if ok {
		delete(podInfoMap, name)
	}
	m.mutex.Unlock()
}

func (m *podMap) get(namespace string, name string) (*K8sPodInfo, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	podInfoMap, ok := m.Info[namespace]
	if !ok {
		return nil, false
	}
	podInfo, ok := podInfoMap[name]
	if !ok {
		return nil, false
	}
	return podInfo, true
}

// getPodsMatchSelectors gets K8sPodInfo(s) whose labels match with selectors in such namespace.
// Return empty slice if not found. Note there may be multiple match.
func (m *podMap) getPodsMatchSelectors(namespace string, selectors map[string]string) []*K8sPodInfo {
	retPodInfoSlice := make([]*K8sPodInfo, 0)
	if len(selectors) == 0 {
		return retPodInfoSlice
	}
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	podInfoMap, ok := m.Info[namespace]
	if !ok {
		return retPodInfoSlice
	}
	for _, podInfo := range podInfoMap {
		if SelectorsMatchLabels(selectors, podInfo.Labels) {
			retPodInfoSlice = append(retPodInfoSlice, podInfo)
		}
	}
	return retPodInfoSlice
}

// SelectorsMatchLabels return true only if labels match all [keys:values] with selectors
func SelectorsMatchLabels(selectors map[string]string, labels map[string]string) bool {
	for key, value := range selectors {
		if labelValue, ok := labels[key]; !ok || labelValue != value {
			return false
		}
	}
	return true
}

func PodWatch(clientSet *kubernetes.Clientset, graceDeletePeriod time.Duration) {
	stopper := make(chan struct{})
	defer close(stopper)

	factory := informers.NewSharedInformerFactory(clientSet, 0)
	podInformer := factory.Core().V1().Pods()
	informer := podInformer.Informer()
	defer runtime.HandleCrash()

	// Start informer, list & watch
	go factory.Start(stopper)

	if !cache.WaitForCacheSync(stopper, informer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}
	// 每隔10s循环检查是否需要删除pod
	go podDeleteLoop(10*time.Second, graceDeletePeriod, stopper)
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    onAdd,
		UpdateFunc: onUpdate,
		DeleteFunc: onDelete,
	})
	// TODO: use workqueue to avoid blocking
	<-stopper
}

func onAdd(obj interface{}) {
	pod := obj.(*corev1.Pod)
	log.Infof("add pod info %#v", pod)
}

func onUpdate(objOld interface{}, objNew interface{}) {
	oldPod := objOld.(*corev1.Pod)
	newPod := objNew.(*corev1.Pod)
	if oldPod.ResourceVersion == newPod.ResourceVersion {
		// Periodic resync will send update events for all known pods.
		// Two different versions of the same pod will always have different RVs.
		return
	}
	log.Infof("update pod info %#v", newPod)
}

func onDelete(obj interface{}) {
	pod := obj.(*corev1.Pod)
	log.Infof("delete pod info %#v", pod)
}
