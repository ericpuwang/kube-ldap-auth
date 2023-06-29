package options

import (
	"fmt"
	"github.com/periky/kube-ldap-auth/pkg/authn"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	cliflag "k8s.io/component-base/cli/flag"
	"net/url"
	"path"
)

type KubeLdapAuthOptions struct {
	// InsecurePort http端口
	InsecurePort int
	// SecurePort https端口,该端口不为零时TLS为必选项
	SecurePort int

	// Upstream 上游服务地址
	Upstream string
	// UpstreamForceH2c 强制h2c(grpc)
	UpstreamForceH2c bool
	// TLS tls证书配置
	TLS *TLSConfig
	// KubeConfig KubeConfig文件路径
	KubeConfig string
	// AllowPaths 白名单接口列表
	AllowPaths []string

	AuthnConfig *authn.Config
}

type TLSConfig struct {
	CertFile     string
	KeyFile      string
	MinVersion   string
	CipherSuites []string

	UpstreamCAFile             string
	UpstreamClientCertFile     string
	UpstreamClientKeyFile      string
	UpstreamInsecureTransport  bool
	UpstreamInsecureSkipVerify bool
}

func NewKubeLdapAuthOptions() *KubeLdapAuthOptions {
	return &KubeLdapAuthOptions{
		InsecurePort: 8086,
		SecurePort:   8443,
		TLS: &TLSConfig{
			MinVersion: "VersionTLS12",
		},
		AuthnConfig: &authn.Config{
			Header: &authn.HeaderConfig{},
			Ldap:   &authn.LdapConfig{},
		},
		AllowPaths: []string{"/metrics", "/health"},
	}
}

func (option *KubeLdapAuthOptions) Flags() cliflag.NamedFlagSets {
	namedFlagSets := cliflag.NamedFlagSets{}
	fs := namedFlagSets.FlagSet("kube-ldap-auth")

	fs.IntVar(&option.InsecurePort, "insecure-port", option.InsecurePort, "http服务端口地址")
	fs.IntVar(&option.SecurePort, "secure-port", option.SecurePort, "https服务端口地址")
	fs.StringVar(&option.Upstream, "upstream", option.Upstream, "上游服务URL")
	fs.BoolVar(&option.UpstreamForceH2c, "upstream-force-h2c", option.UpstreamForceH2c, "强制使用H2C")
	fs.StringSliceVar(&option.AllowPaths, "allow-paths", option.AllowPaths, "白名单接口列表")

	fs.StringVar(&option.TLS.CertFile, "tls-cert-file", option.TLS.CertFile, "x509 certificate file")
	fs.StringVar(&option.TLS.KeyFile, "tls-private-key-file", option.TLS.KeyFile, "x509 private key file")
	fs.StringVar(&option.TLS.MinVersion, "tls-min-version", option.TLS.MinVersion, "tls最小支持版本")
	fs.StringVar(&option.TLS.UpstreamCAFile, "upstream-ca-file", option.TLS.UpstreamCAFile, "ca file")
	fs.StringVar(&option.TLS.UpstreamClientCertFile, "upstream-client-cert-file", option.TLS.UpstreamClientCertFile, "上游服务客户端证书")
	fs.StringVar(&option.TLS.UpstreamClientKeyFile, "upstream-client-key-file", option.TLS.UpstreamClientKeyFile, "上游服务客户端私钥证书")
	fs.BoolVar(&option.TLS.UpstreamInsecureTransport, "upstream-insecure-transport", option.TLS.UpstreamInsecureTransport, "禁用客户端连接的传输安全性")
	fs.BoolVar(&option.TLS.UpstreamInsecureSkipVerify, "upstream-insecure-skip-verify", option.TLS.UpstreamInsecureSkipVerify, "不验证服务端证书验证")

	fs.StringVar(&option.KubeConfig, "kubeconfig", option.KubeConfig, "kubeconfig文件路径")

	fs.BoolVar(&option.AuthnConfig.Header.Enabled, "auth-header-fields-enabled", false, "如果设置为true,kube-ldap-auth将认证字段写入上游请求的header中")
	fs.StringVar(&option.AuthnConfig.Header.UserFieldName, "auth-header-user-field-name", "x-remote-user", "http请求header,包含当前请求认证的用户名")
	fs.StringVar(&option.AuthnConfig.Header.GroupsFieldName, "auth-header-groups-field-name", "x-remote-groups", "http请求header,包含当前请求认证用户所在组")
	fs.StringVar(&option.AuthnConfig.Header.GroupSeparator, "auth-header-groups-separator", "|", "组名之间的分隔符")
	fs.StringVar(&option.AuthnConfig.Ldap.ServerURI, "auth-ldap-server-uri", "", "ldap地址")

	return namedFlagSets
}

func (option *KubeLdapAuthOptions) Complete() {

}

func (option *KubeLdapAuthOptions) Validate() error {
	var allErrs []error

	if (option.TLS.KeyFile != "" && option.TLS.CertFile == "") || (option.TLS.KeyFile == "" && option.TLS.CertFile != "") {
		allErrs = append(allErrs, fmt.Errorf("keyFile和certFile必须同时存在. [keyFile: %s, certFile: %s]", option.TLS.KeyFile, option.TLS.CertFile))
	}

	if (option.TLS.UpstreamClientKeyFile != "" && option.TLS.UpstreamClientCertFile == "") || (option.TLS.UpstreamClientKeyFile == "" && option.TLS.UpstreamClientCertFile != "") {
		allErrs = append(allErrs, fmt.Errorf("upstreamClientKeyFile和upustreamClientCertFile必须同时存在. [upstreamClientKeyFile: %s, upustreamClientCertFile: %s]", option.TLS.UpstreamClientKeyFile, option.TLS.UpstreamClientCertFile))
	}

	if _, err := url.Parse(option.Upstream); err != nil {
		allErrs = append(allErrs, fmt.Errorf("解析 --upstream失败. err: %v", err))
	}

	for _, pathAllowed := range option.AllowPaths {
		_, err := path.Match(pathAllowed, "")
		if err != nil {
			allErrs = append(allErrs, fmt.Errorf("无效的allowPath: %s", pathAllowed))
		}
	}

	return utilerrors.NewAggregate(allErrs)
}

func (option *KubeLdapAuthOptions) KubeClientOrDie() kubernetes.Interface {
	var (
		restCfg *rest.Config
		err     error
	)
	if option.KubeConfig != "" {
		restCfg, err = clientcmd.BuildConfigFromFlags("", option.KubeConfig)
	} else {
		restCfg, err = rest.InClusterConfig()
	}
	if err != nil {
		panic(err)
	}

	return kubernetes.NewForConfigOrDie(restCfg)
}
