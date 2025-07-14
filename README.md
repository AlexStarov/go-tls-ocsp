# go-tls-ocsp

📡 **Go package for automatic OCSP stapling in HTTPS servers**

This package provides:
- 🔒 Secure OCSP stapling via `GetCertificate` in `tls.Config`
- 🔄 Automated background refresh of OCSP responses
- ⚡ Fast TLS handshakes with preloaded certificate status


## 📦 Installation

go get github.com/your-username/go-tls-ocsp


## 🧩 Usage

```go
bundle := tlsocsp.CertBundle{
    CertPEM:   []byte(cert),  // ваш сертификат в PEM-формате
    KeyPEM:    []byte(key),   // ваш закрытый ключ в PEM-формате
    IssuerPEM: []byte(ca),    // PEM-сертификат центра сертификации
}

updater := tlsocsp.NewUpdater(bundle)
cache   := tlsocsp.NewCache(updater, 6*time.Hour)

server := &http.Server{
    Addr:    ":443",
    Handler: yourHandler,
    TLSConfig: &tls.Config{
        GetCertificate: cache.GetCertificateFunc(),
    },
}

// Запускаем HTTPS-сервер
log.Fatal(server.ListenAndServeTLS("", ""))


## 🛡️ License
This repository is published under a Custom Proprietary Read-Only License.

🔍 The source code is fully visible and accessible for educational or curiosity purposes, but:

❌ Usage is prohibited — you may not execute or deploy this software

❌ Modification is prohibited — you may not change or build upon this code

❌ Redistribution is prohibited — you may not copy or share this repository

❌ Commercial use is strictly forbidden

✅ Reading and analysis for personal education is allowed

Any violations of these terms may result in legal consequences.

For full terms, see LICENSE.

If you wish to use or adapt the code — you must obtain explicit written permission from the author.

Author: Сергей License Year: 2025