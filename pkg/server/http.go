package server

import (
	"context"
	"fmt"
	"github.com/periky/kube-ldap-auth/cmd/app/options"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"k8s.io/klog/v2"
	"net"
	"net/http"
)

type httpServer struct {
	srv  *http.Server
	port int
}

func NewHttpServer(handler *http.ServeMux, cfg *options.KubeLdapAuthOptions) Server {
	return &httpServer{
		srv:  &http.Server{Handler: h2c.NewHandler(handler, &http2.Server{})},
		port: cfg.InsecurePort,
	}
}

func (s *httpServer) Start() {
	klog.Infof("Starting TCP socket on %v", s.port)
	listen, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		panic(err)
	}

	go func() {
		if err := s.srv.Serve(listen); err != nil {
			klog.ErrorS(err, "http服务启动失败")
		}
	}()
}

func (s *httpServer) Stop(ctx context.Context) {
	if err := s.srv.Shutdown(ctx); err != nil {
		klog.ErrorS(err, "强制终止http服务", "port", s.port)
	}
	klog.Info("http服务已终止.")
}
