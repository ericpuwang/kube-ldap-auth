# kube-ldap-auth

`kube-ldap-auth`是一个反向代理服务，基于LDAP的统一认证和k8s RBAC鉴权体系。

# 启动参数

`--allow-paths` strings                    白名单接口列表 (default [/metrics,/health])
`--auth-header-fields-enabled`             如果设置为true,kube-ldap-auth将认证字段写入上游请求的header中
`--auth-header-groups-field-name` string   http请求header,包含当前请求认证用户所在组 (default "x-remote-groups")
`--auth-header-groups-separator` string    组名之间的分隔符 (default "|")
`--auth-header-user-field-name` string     http请求header,包含当前请求认证的用户名 (default "x-remote-user")
`--auth-ldap-server-uri` string            ldap地址
`--auth-ldap-base-dn` string               ldap地址
`--insecure-port` int                      http服务端口地址 (default 8086)
`--kubeconfig` string                      kubeconfig文件路径
`--secure-port` int                        https服务端口地址 (default 8443)
`--tls-cert-file` string                   x509 certificate file
`--tls-min-version` string                 tls最小支持版本 (default "VersionTLS12")
`--tls-private-key-file` string            x509 private key file
`--upstream` string                        上游服务URL
`--upstream-ca-file` string                ca file
`--upstream-client-cert-file` string       上游服务客户端证书
`--upstream-client-key-file` string        上游服务客户端私钥证书
`--upstream-force-h2c`                     强制使用H2C
`--upstream-insecure-skip-verify`          不验证服务端证书验证
`--upstream-insecure-transport`            禁用客户端连接的传输安全性

# 环境变量

`LDAP_ADMIN_DN`                            LDAP管理员用户名
`LDAP_ADMIN_PASSWD`                        LDAP管理员密码