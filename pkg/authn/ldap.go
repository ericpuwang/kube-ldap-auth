package authn

import (
	"encoding/json"
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
	body := &LoginRequest{}
	if err := json.NewDecoder(req.Body).Decode(body); err != nil {
		klog.ErrorS(err, "入参解析失败")
		return nil, false, err
	}

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
		os.Getenv("LDAP_BASE_DN"),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&(objectClass=posixAccount)(uid=%s))", body.Username), // Filter
		nil,
		nil,
	))
	if err != nil {
		klog.ErrorS(err, "LDAP搜索异常", "objectClass", "posixAccount", "uid", body.Username, "baseDn", os.Getenv("LDAP_BASE_DN"))
		return nil, false, err
	}

	// 找到objectClass=posixGroup且memberUid={body.Username}的记录
	result, err := conn.Search(ldap.NewSearchRequest(
		os.Getenv("LDAP_BASE_DN"),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&(objectClass=posixGroup)(memberUid=%s))", body.Username), // Filter
		nil,
		nil,
	))
	if err != nil {
		klog.ErrorS(err, "LDAP搜索异常", "objectClass", "posixGroup", "memberUid", body.Username, "baseDn", os.Getenv("LDAP_BASE_DN"))
		return nil, false, err
	}
	if len(result.Entries) == 0 {
		klog.V(2).InfoS("用户不存在", "username", body.Username, "baseDn", os.Getenv("LDAP_BASE_DN"))
		return nil, false, errors.New("用户名或密码错误")
	}

	if err := conn.Bind(userResult.Entries[0].DN, body.Password); err != nil {
		klog.ErrorS(err, "认证失败", "user", body.Username)
		return nil, false, errors.New("用户名或密码错误")
	}
	klog.V(3).Info(fmt.Sprintf("User %s Authenticated successfuly!", body.Username))

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
