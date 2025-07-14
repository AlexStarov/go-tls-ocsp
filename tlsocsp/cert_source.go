package tlsocsp

import (
    "crypto/tls"
)

type Source interface {
    GenerateTLSCertificate() (*tls.Certificate, error)
}
