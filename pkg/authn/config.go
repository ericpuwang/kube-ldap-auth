package authn

type Config struct {
	Header *HeaderConfig
	Ldap   *LdapConfig
}

type HeaderConfig struct {
	Enabled         bool
	UserFieldName   string
	GroupsFieldName string
	GroupSeparator  string
}

type LdapConfig struct {
	ServerURI string // 127.0.0.1:389
}

type LoginRequest struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}
