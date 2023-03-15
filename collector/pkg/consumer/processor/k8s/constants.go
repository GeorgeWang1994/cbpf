package k8s

import "time"

const (
	// AuthTypeNone means no auth is required
	AuthTypeNone AuthType = "none"
	// AuthTypeServiceAccount means to use the built-in service account that
	// K8s automatically provisions for each pod.
	AuthTypeServiceAccount AuthType = "serviceAccount"
	// AuthTypeKubeConfig uses local credentials like those used by kubectl.
	AuthTypeKubeConfig AuthType = "kubeConfig"
	// Default kubeconfig path
	DefaultKubeConfigPath string = "~/.kube/config"
	// Default grace delete period is 60 seconds
	DefaultGraceDeletePeriod time.Duration = time.Second * 60
)
