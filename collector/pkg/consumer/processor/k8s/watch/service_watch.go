package watch

import (
	k8s2 "collector/pkg/consumer/processor/k8s"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"sync"
)

type ServiceMap struct {
	// Service name could be duplicated in different namespace, so here
	// service name must not be the key of map. Therefore, a map with the
	// following structure is constructed.
	//
	// namespace1:
	//   servicename1: ServiceInfo{}
	//   servicename2: ServiceInfo{}
	// namespace2:
	//   servicename1: ServiceInfo{}
	ServiceMap map[string]map[string]*k8s2.K8sServiceInfo
	mut        sync.RWMutex
}

var GlobalServiceInfo = newServiceMap()
var serviceUpdatedMutex sync.Mutex

func newServiceMap() *ServiceMap {
	return &ServiceMap{
		ServiceMap: make(map[string]map[string]*k8s2.K8sServiceInfo),
		mut:        sync.RWMutex{},
	}
}

// GetServiceMatchLabels gets K8sServiceInfos which match labels in such namespace.
// Return empty slice if not found. Note there may be multiple matches.
func (s *ServiceMap) GetServiceMatchLabels(namespace string, labels map[string]string) []*k8s2.K8sServiceInfo {
	s.mut.RLock()
	defer s.mut.RUnlock()
	retServiceInfoSlice := make([]*k8s2.K8sServiceInfo, 0)
	serviceNameMap, ok := s.ServiceMap[namespace]
	if !ok {
		return retServiceInfoSlice
	}
	for _, serviceInfo := range serviceNameMap {
		if len(serviceInfo.Selector) == 0 {
			continue
		}
		if SelectorsMatchLabels(serviceInfo.Selector, labels) {
			retServiceInfoSlice = append(retServiceInfoSlice, serviceInfo)
		}
	}
	return retServiceInfoSlice
}

func (s *ServiceMap) add(info *k8s2.K8sServiceInfo) {
	s.mut.Lock()
	serviceNameMap, ok := s.ServiceMap[info.Namespace]
	if !ok {
		serviceNameMap = make(map[string]*k8s2.K8sServiceInfo)
	}
	serviceNameMap[info.ServiceName] = info
	s.ServiceMap[info.Namespace] = serviceNameMap
	s.mut.Unlock()
}

func (s *ServiceMap) delete(namespace string, serviceName string) {
	s.mut.Lock()
	serviceNameMap, ok := s.ServiceMap[namespace]
	if ok {
		serviceInfo, ok := serviceNameMap[serviceName]
		if ok {
			// Set the value empty via its pointer, in which way all serviceInfo related to
			// K8sPodInfo.K8sServiceInfo will be set to empty.
			// The following data will be affected:
			// - K8sMetaDataCache.containerIdInfo
			// - K8sMetaDataCache.ipContainerInfo
			// - K8sMetaDataCache.ipServiceInfo
			serviceInfo.EmptySelf()
		}
	}
	s.mut.Unlock()
}

func ServiceWatch(clientSet *kubernetes.Clientset) {
	stopper := make(chan struct{})
	defer close(stopper)

	factory := informers.NewSharedInformerFactory(clientSet, 0)
	serviceInformer := factory.Core().V1().Services()
	informer := serviceInformer.Informer()
	defer runtime.HandleCrash()

	go factory.Start(stopper)

	if !cache.WaitForCacheSync(stopper, informer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    onAddService,
		UpdateFunc: onUpdateService,
		DeleteFunc: onDeleteService,
	})
	// TODO: use workqueue to avoid blocking
	<-stopper
}

func onAddService(obj interface{}) {
	service := obj.(*corev1.Service)
	sI := &k8s2.K8sServiceInfo{
		Ip:          service.Spec.ClusterIP,
		ServiceName: service.Name,
		Namespace:   service.Namespace,
		IsNodePort:  service.Spec.Type == "NodePort",
		Selector:    service.Spec.Selector,
	}
	GlobalServiceInfo.add(sI)
}

func onUpdateService(objOld interface{}, objNew interface{}) {
	oldSvc := objOld.(*corev1.Service)
	newSvc := objNew.(*corev1.Service)
	if oldSvc.ResourceVersion == newSvc.ResourceVersion {
		return
	}
	serviceUpdatedMutex.Lock()
	// TODO: re-implement the updated logic to reduce computation
	onDeleteService(objOld)
	onAddService(objNew)
	serviceUpdatedMutex.Unlock()
}

func onDeleteService(obj interface{}) {
	service := obj.(*corev1.Service)
	// 'delete' will delete all such service in MetaDataCache
	GlobalServiceInfo.delete(service.Namespace, service.Name)
	ip := service.Spec.ClusterIP
	if ip == "" || ip == "None" {
		return
	}
	for _, port := range service.Spec.Ports {
		k8s2.MetaDataCache.DeleteServiceByIpPort(ip, uint32(port.Port))
		if service.Spec.Type == "NodePort" {
			nodeAddresses := GlobalNodeInfo.getAllNodeAddresses()
			for _, nodeAddress := range nodeAddresses {
				k8s2.MetaDataCache.DeleteServiceByIpPort(nodeAddress, uint32(port.NodePort))
			}
		}
	}
}
