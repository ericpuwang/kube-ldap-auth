package authn

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/klog/v2"
	"net/http"
	"os"
	"strings"
)

type LdapAuthenticator struct {
	config *LdapConfig
}

var _ authenticator.Request = (*LdapAuthenticator)(nil)

func NewLdapAuthenticator(config *LdapConfig) (*LdapAuthenticator, error) {
	return &LdapAuthenticator{config: config}, nil
}

func (auth *LdapAuthenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	authHeader := strings.TrimSpace(req.Header.Get("Authorization"))
	if authHeader == "" {
		return nil, false, nil
	}
	parts := strings.SplitN(authHeader, " ", 3)
	if len(parts) < 2 || strings.ToLower(parts[0]) != "basic" {
		return nil, false, nil
	}

	authHeaderVal := parts[1]

	// Empty bearer tokens aren't valid
	if len(authHeaderVal) == 0 {
		return nil, false, nil
	}

	token, err := base64.StdEncoding.DecodeString(authHeaderVal)
	if err != nil {
		klog.Error(err)
		return nil, false, err
	}
	userInfo := strings.Split(string(token), ":")

	// 连接到ldap server
	conn, err := ldap.Dial("tcp", auth.config.ServerURI)
	if err != nil {
		klog.ErrorS(err, "无法连接LDAP服务器")
		return nil, false, err
	}

	// ldap admin authenticate
	if err := conn.Bind(os.Getenv("LDAP_ADMIN_DN"), os.Getenv("LDAP_ADMIN_PASSWD")); err != nil {
		klog.ErrorS(err, "LDAP管理员认证失败")
		return nil, false, err
	}

	// 找到objectClass=posixAccount且uid={body.Username}的记录
	userResult, err := conn.Search(ldap.NewSearchRequest(
		auth.config.BaseDn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&(objectClass=posixAccount)(uid=%s))", userInfo[0]), // Filter
		nil,
		nil,
	))
	if err != nil {
		klog.ErrorS(err, "LDAP搜索异常", "objectClass", "posixAccount", "uid", userInfo[0], "baseDn", auth.config.BaseDn)
		return nil, false, err
	}

	// 找到objectClass=groupOfNames且member={dn}的记录
	result, err := conn.Search(ldap.NewSearchRequest(
		auth.config.BaseDn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&(objectClass=groupOfNames)(member=%s))", userResult.Entries[0].DN), // Filter
		nil,
		nil,
	))
	if err != nil {
		klog.ErrorS(err, "LDAP搜索异常", "objectClass", "posixGroup", "memberUid", userInfo[0], "baseDn", auth.config.BaseDn)
		return nil, false, err
	}
	if len(result.Entries) == 0 {
		klog.V(2).InfoS("用户不存在", "username", userInfo[0], "baseDn", auth.config.BaseDn)
		return nil, false, errors.New("用户名或密码错误")
	}

	if err := conn.Bind(userResult.Entries[0].DN, userInfo[1]); err != nil {
		klog.ErrorS(err, "认证失败", "user", userInfo[0])
		return nil, false, errors.New("用户名或密码错误")
	}
	klog.V(3).Info(fmt.Sprintf("User %s Authenticated successfuly!", userInfo[0]))

	authUser := new(user.DefaultInfo)
	for _, v := range result.Entries {
		attribute := v.GetAttributeValue("objectClass")
		if strings.Contains(attribute, "posixGroup") {
			authUser.Groups = append(authUser.Groups, v.GetAttributeValue("cn"))
		}
	}

	u := userResult.Entries[0].GetAttributeValue("uid")
	authUser.UID = u
	authUser.Name = u
	return &authenticator.Response{User: authUser}, true, nil
}
