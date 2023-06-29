package app

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/periky/kube-ldap-auth/cmd/app/options"
	"net"
	"net/http"
	"os"
	"time"
)

func initUpstreamTransport(tlsOpt *options.TLSConfig) (http.RoundTripper, error) {
	if tlsOpt.UpstreamCAFile == "" {
		return http.DefaultTransport, nil
	}

	caPem, err := os.ReadFile(tlsOpt.UpstreamCAFile)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caPem); !ok {
		return nil, err
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
	}

	var certKeyPair tls.Certificate
	if tlsOpt.UpstreamClientCertFile != "" {
		certKeyPair, err = tls.LoadX509KeyPair(tlsOpt.UpstreamClientCertFile, tlsOpt.UpstreamClientKeyFile)
		if err != nil {
			return nil, err
		}
	}
	if certKeyPair.Certificate != nil {
		transport.TLSClientConfig.Certificates = []tls.Certificate{certKeyPair}
	}

	return transport, nil
}
