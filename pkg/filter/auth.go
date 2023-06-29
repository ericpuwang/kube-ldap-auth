package filter

import (
	"context"
	"errors"
	"github.com/periky/kube-ldap-auth/pkg/authn"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	"k8s.io/apiserver/pkg/endpoints/request"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/klog/v2"
	"net/http"
	"strings"
)

func WithAuthHeaders(cfg *authn.HeaderConfig, handler http.Handler) http.Handler {
	if !cfg.Enabled {
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		u, ok := request.UserFrom(req.Context())
		if ok {
			req.Header.Set(cfg.UserFieldName, u.GetName())
			req.Header.Set(cfg.GroupsFieldName, strings.Join(u.GetGroups(), cfg.GroupSeparator))
		}

		handler.ServeHTTP(w, req)
	})
}

func GetAuthorizerAttributes(ctx context.Context) (authorizer.Attributes, error) {
	attribs := authorizer.AttributesRecord{}

	user, ok := request.UserFrom(ctx)
	if ok {
		attribs.User = user
	}

	requestInfo, found := request.RequestInfoFrom(ctx)
	if !found {
		return nil, errors.New("no RequestInfo found in the context")
	}

	// Start with common attributes that apply to resource and non-resource requests
	attribs.ResourceRequest = requestInfo.IsResourceRequest
	attribs.Path = requestInfo.Path
	attribs.Verb = requestInfo.Verb

	attribs.APIGroup = requestInfo.APIGroup
	attribs.APIVersion = requestInfo.APIVersion
	attribs.Resource = requestInfo.Resource
	attribs.Subresource = requestInfo.Subresource
	attribs.Namespace = requestInfo.Namespace
	attribs.Name = requestInfo.Name

	return &attribs, nil
}

func WithAuthorization(a authorizer.Authorizer, handler http.Handler) http.Handler {
	if a == nil {
		klog.Warning("Authorization is disabled")
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()

		attributes, err := GetAuthorizerAttributes(ctx)
		if err != nil {
			responsewriters.InternalError(w, req, err)
			return
		}
		authorized, reason, err := a.Authorize(ctx, attributes)
		// an authorizer like RBAC could encounter evaluation errors and still allow the request, so authorizer decision is checked before error here.
		if authorized == authorizer.DecisionAllow {
			handler.ServeHTTP(w, req)
			return
		}
		if err != nil {
			responsewriters.InternalError(w, req, err)
			return
		}

		klog.V(4).InfoS("Forbidden", "URI", req.RequestURI, "Reason", reason)
		scheme := runtime.NewScheme()
		negotiatedSerializer := serializer.NewCodecFactory(scheme).WithoutConversion()
		responsewriters.Forbidden(ctx, attributes, w, req, reason, negotiatedSerializer)
	})
}

func WithAuthentication(authReq authenticator.Request, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		res, ok, err := authReq.AuthenticateRequest(req)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		req = req.WithContext(request.WithUser(req.Context(), res.User))
		handler.ServeHTTP(w, req)
	})
}

func NewRequestInfoResolver() *apirequest.RequestInfoFactory {
	apiPrefixes := sets.NewString(strings.Trim(server.APIGroupPrefix, "/")) // all possible API prefixes
	legacyAPIPrefixes := sets.String{}                                      // APIPrefixes that won't have groups (legacy)
	apiPrefixes.Insert(strings.Trim(server.DefaultLegacyAPIPrefix, "/"))
	legacyAPIPrefixes.Insert(strings.Trim(server.DefaultLegacyAPIPrefix, "/"))

	return &apirequest.RequestInfoFactory{
		APIPrefixes:          apiPrefixes,
		GrouplessAPIPrefixes: legacyAPIPrefixes,
	}
}
