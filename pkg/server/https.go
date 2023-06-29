package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/periky/kube-ldap-auth/cmd/app/options"
	certutil "k8s.io/client-go/util/cert"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/klog/v2"
	"net"
	"net/http"
	"os"
)

type httpServerWithTLS struct {
	srv       *http.Server
	tlsConfig *options.TLSConfig
	port      int
}

func NewHttpsServer(handler *http.ServeMux, cfg *options.KubeLdapAuthOptions) Server {
	hst := &httpServerWithTLS{
		srv:       &http.Server{Handler: handler, TLSConfig: &tls.Config{}},
		tlsConfig: cfg.TLS,
		port:      cfg.SecurePort,
	}

	return hst
}

func (s *httpServerWithTLS) Start() {
	if err := s.injectTlsConfig(); err != nil {
		panic(err)
	}

	klog.Infof("Starting TCP socket on %v", s.port)
	listen, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		panic(err)
	}
	tlsListener := tls.NewListener(listen, s.srv.TLSConfig)
	go func() {
		if err := s.srv.Serve(tlsListener); err != nil {
			klog.ErrorS(err, "https服务启动失败")
		}
	}()
}

func (s *httpServerWithTLS) Stop(ctx context.Context) {
	if err := s.srv.Shutdown(ctx); err != nil {
		klog.ErrorS(err, "强制终止https服务", "port", s.port)
	}
	klog.Info("https服务已终止.")
}

func (s *httpServerWithTLS) injectTlsConfig() error {
	version, err := cliflag.TLSVersion(s.tlsConfig.MinVersion)
	if err != nil {
		klog.ErrorS(err, "无效的TLS版本", "version", s.tlsConfig.MinVersion)
		return err
	}
	cipherSuiteIDs, err := cliflag.TLSCipherSuites(s.tlsConfig.CipherSuites)
	if err != nil {
		klog.ErrorS(err, "转换TLS CipherSuite到ID失败")
		return err
	}

	s.srv.TLSConfig.CipherSuites = cipherSuiteIDs
	s.srv.TLSConfig.MinVersion = version
	s.srv.TLSConfig.ClientAuth = tls.RequestClientCert

	if s.tlsConfig.CertFile == "" && s.tlsConfig.KeyFile == "" {
		klog.Info("生成自签证书")
		host, err := os.Hostname()
		if err != nil {
			klog.ErrorS(err, "获取主机名失败")
			return err
		}
		certBytes, keyBytes, err := certutil.GenerateSelfSignedCertKey(host, nil, nil)
		if err != nil {
			klog.ErrorS(err, "生成自签证书失败")
			return err
		}
		cert, err := tls.X509KeyPair(certBytes, keyBytes)
		if err != nil {
			klog.ErrorS(err, "加载自签证书失败")
			return err
		}
		s.srv.TLSConfig.Certificates = []tls.Certificate{cert}

		return nil
	}

	klog.Info("Reading certificate files")
	cert, err := tls.LoadX509KeyPair(s.tlsConfig.CertFile, s.tlsConfig.KeyFile)
	if err != nil {
		klog.ErrorS(err, "加载证书文件异常")
		return err
	}
	s.srv.TLSConfig.Certificates = []tls.Certificate{cert}
	return nil
}
