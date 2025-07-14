package tlsocsp

import (
	"crypto/tls"
	"errors"
	"sync"
	"time"
)

type Cache struct {
	source     Source
	tlsCert    *tls.Certificate
	lastUpdate time.Time
	interval   time.Duration
	mu         sync.RWMutex
}

func NewCache(source Source, interval time.Duration) *Cache {
	cache := &Cache{source: source, interval: interval}
	cache.Refresh()
	go cache.autoUpdate()
	return cache
}

func (c *Cache) autoUpdate() {
	for {
		time.Sleep(c.interval)
		c.Refresh()
	}
}

func (c *Cache) Refresh() {
	c.mu.Lock()
	defer c.mu.Unlock()

	tlsCert, err := c.source.GenerateTLSCertificate()
	if err != nil {
		// логирование внутри Source
		return
	}
	c.tlsCert = tlsCert
	c.lastUpdate = time.Now()
}

func (c *Cache) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c.mu.RLock()
		defer c.mu.RUnlock()
		if c.tlsCert == nil {
			return nil, errors.New("no tls certificate available")
		}
		return c.tlsCert, nil
	}
}
