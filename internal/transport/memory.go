package transport

import (
	"sync"

	"github.com/veilvpn/veil/internal/config"
)

// MemMemory is a simple in-memory Memory implementation. A persistent
// (on-disk) implementation backing the client's DataDir lands with the daemon.
type MemMemory struct {
	mu   sync.Mutex
	seen map[string]config.TransportName
}

// NewMemMemory returns an empty in-memory transport memory.
func NewMemMemory() *MemMemory {
	return &MemMemory{seen: make(map[string]config.TransportName)}
}

func (m *MemMemory) Preferred(networkID string) (config.TransportName, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.seen[networkID]
	return t, ok
}

func (m *MemMemory) Remember(networkID string, t config.TransportName) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen[networkID] = t
}
