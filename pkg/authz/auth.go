package authz

import (
	"errors"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/server/options"
	authorizationclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"time"
)

func NewSarAuthorizer(client authorizationclient.AuthorizationV1Interface) (authorizer.Authorizer, error) {
	if client == nil {
		return nil, errors.New("no client provided, cannot use webhook authorization")
	}

	authorizerConfig := authorizerfactory.DelegatingAuthorizerConfig{
		SubjectAccessReviewClient: client,
		// Defaults are most probably taken from: kubernetes/pkg/kubelet/apis/config/v1beta1/defaults.go
		// Defaults that are more reasonable: apiserver/pkg/server/options/authorization.go
		AllowCacheTTL:       5 * time.Minute,
		DenyCacheTTL:        30 * time.Second,
		WebhookRetryBackoff: options.DefaultAuthWebhookRetryBackoff(),
	}
	return authorizerConfig.New()
}
