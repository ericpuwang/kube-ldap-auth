package server

import (
	"context"
	"github.com/periky/kube-ldap-auth/cmd/app/options"
	"net/http"
)

type Server interface {
	Start()
	Stop(context.Context)
}

type server struct {
	servers []Server
}

func NewServer(handler *http.ServeMux, cfg *options.KubeLdapAuthOptions) Server {
	httpSrv := NewHttpServer(handler, cfg)
	httpsSrv := NewHttpsServer(handler, cfg)
	srv := &server{
		servers: []Server{httpSrv, httpsSrv},
	}

	return srv
}

func (s *server) Start() {
	for _, srv := range s.servers {
		srv.Start()
	}
}

func (s *server) Stop(ctx context.Context) {
	for _, srv := range s.servers {
		srv.Stop(ctx)
	}
}
