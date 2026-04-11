package fragment

import "sync"

// sinusoidalRegistry stores SinusoidalConfig per shortId.
// Populated during config parsing, consumed by dialer/hub.
var (
	sinusoidalRegistry     = make(map[string]*SinusoidalConfig)
	sinusoidalRegistryLock sync.RWMutex
	sinusoidalGlobalConfig *SinusoidalConfig
	sinusoidalGlobalLock   sync.RWMutex
)

// RegisterSinusoidal stores a sinusoidal config for a given shortId.
func RegisterSinusoidal(shortId string, cfg *SinusoidalConfig) {
	sinusoidalRegistryLock.Lock()
	defer sinusoidalRegistryLock.Unlock()
	sinusoidalRegistry[shortId] = cfg
}

// GetSinusoidal retrieves the sinusoidal config for a given shortId.
// Returns nil if not registered (sinusoidal modulation disabled).
func GetSinusoidal(shortId string) *SinusoidalConfig {
	sinusoidalRegistryLock.RLock()
	defer sinusoidalRegistryLock.RUnlock()
	return sinusoidalRegistry[shortId]
}

// SetGlobalSinusoidal sets a global sinusoidal config (for server side, any shortId).
func SetGlobalSinusoidal(cfg *SinusoidalConfig) {
	sinusoidalGlobalLock.Lock()
	defer sinusoidalGlobalLock.Unlock()
	sinusoidalGlobalConfig = cfg
}

// GetGlobalSinusoidal returns the global sinusoidal config.
func GetGlobalSinusoidal() *SinusoidalConfig {
	sinusoidalGlobalLock.RLock()
	defer sinusoidalGlobalLock.RUnlock()
	return sinusoidalGlobalConfig
}
