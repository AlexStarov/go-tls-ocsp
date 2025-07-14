package tlsocsp

import (
	"crypto/tls"
	"errors"
	"log"
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

	log.Println("[tlsocsp] Refreshing OCSP stapled certificate")

	tlsCert, err := c.source.GenerateTLSCertificate()
	if err != nil {
		log.Printf("[tlsocsp] Error generating TLS certificate: %v\n", err)
		return
	}
	log.Println("[tlsocsp] Certificate refreshed successfully")

	c.tlsCert = tlsCert
	c.lastUpdate = time.Now()
}

func (c *Cache) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c.mu.RLock()
		defer c.mu.RUnlock()

		if c.tlsCert == nil {
			log.Println("[tlsocsp] No TLS certificate available during handshake")
			return nil, errors.New("no tls certificate available")
		}

		log.Println("[tlsocsp] TLS certificate served successfully")
		return c.tlsCert, nil
	}
}
