package k8s

import "time"

// AuthType describes the type of authentication to use for the K8s API
type AuthType string

// config contains optional settings for connecting to kubernetes.
type config struct {
	KubeAuthType  AuthType
	KubeConfigDir string
	// GraceDeletePeriod controls the delay interval after receiving delete event.
	// The unit is seconds, and the default value is 60 seconds.
	// Should not be lower than 30 seconds.
	GraceDeletePeriod time.Duration
}

type Option func(cfg *config)
