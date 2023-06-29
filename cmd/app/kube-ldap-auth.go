package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/periky/kube-ldap-auth/cmd/app/options"
	"github.com/periky/kube-ldap-auth/pkg/authn"
	"github.com/periky/kube-ldap-auth/pkg/authz"
	"github.com/periky/kube-ldap-auth/pkg/filter"
	"github.com/periky/kube-ldap-auth/pkg/proxy"
	"github.com/periky/kube-ldap-auth/pkg/server"
	"github.com/spf13/cobra"
	"golang.org/x/net/http2"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	genericfilters "k8s.io/apiserver/pkg/server/filters"
	"k8s.io/client-go/rest"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/cli/globalflag"
	"k8s.io/component-base/logs"
	"k8s.io/component-base/term"
	"k8s.io/component-base/version/verflag"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func NewKubeLdapAuthCommand() *cobra.Command {
	opts := options.NewKubeLdapAuthOptions()
	cmd := &cobra.Command{
		Use: "kube-ldap-auth",
		Long: `The kube-ldap-auth is a small HTTP proxy for a single upstream
that can perform RBAC authorization against the Kubernetes API using SubjectAccessReview.`,
		SilenceUsage: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// 抑制client-go的警告内容
			rest.SetDefaultWarningHandler(rest.NoWarnings{})
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()

			fs := cmd.Flags()
			cliflag.PrintFlags(fs)

			opts.Complete()
			if err := opts.Validate(); err != nil {
				return err
			}

			return Run(context.Background(), opts)
		},
		Args: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if len(arg) > 0 {
					return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), args)
				}
			}
			return nil
		},
	}

	fs := cmd.Flags()
	namedFlagSets := opts.Flags()
	verflag.AddFlags(namedFlagSets.FlagSet("global"))
	globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), cmd.Name(), logs.SkipLoggingConfigurationFlags())
	for _, f := range namedFlagSets.FlagSets {
		fs.AddFlagSet(f)
	}

	cols, _, _ := term.TerminalSize(cmd.OutOrStdout())
	cliflag.SetUsageAndHelpFunc(cmd, namedFlagSets, cols)

	return cmd
}

func Run(ctx context.Context, opt *options.KubeLdapAuthOptions) error {
	var (
		authnReq authenticator.Request
		err      error
	)

	authnReq, err = authn.NewLdapAuthenticator(opt.AuthnConfig.Ldap)
	if err != nil {
		return err
	}

	client := opt.KubeClientOrDie()
	sarClient := client.AuthorizationV1()
	sarAuthorizer, err := authz.NewSarAuthorizer(sarClient)
	if err != nil {
		return err
	}

	proxyURL, _ := url.Parse(opt.Upstream)
	upstreamTransport, err := initUpstreamTransport(opt.TLS)
	if err != nil {
		return err
	}

	directHandler := httputil.NewSingleHostReverseProxy(proxyURL)
	directHandler.Transport = upstreamTransport
	if opt.UpstreamForceH2c {
		directHandler.Transport = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		}
	}

	proxyHandler := filter.WithAuthHeaders(opt.AuthnConfig.Header, directHandler)
	proxyHandler = filter.WithAuthorization(sarAuthorizer, proxyHandler)
	proxyHandler = filter.WithAuthentication(authnReq, proxyHandler)
	requestInfoResolver := filter.NewRequestInfoResolver()
	proxyHandler = genericapifilters.WithRequestInfo(proxyHandler, requestInfoResolver)
	proxyHandler = genericfilters.WithPanicRecovery(proxyHandler, requestInfoResolver)

	mux := http.NewServeMux()
	mux.Handle("/", proxy.Handler(opt.AllowPaths, directHandler, proxyHandler))

	srv := server.NewServer(mux, opt)
	srv.Start()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	srv.Stop(shutdownCtx)

	return nil
}
