package proxy

import (
	"net/http"
	"path"
)

func Handler(allowPaths []string, direct, proxy http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		for _, pathAllowed := range allowPaths {
			found, err := path.Match(pathAllowed, req.URL.Path)
			if err != nil {
				http.Error(
					w,
					http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError,
				)
				return
			}

			if !found {
				proxy.ServeHTTP(w, req)
				return
			}
		}

		direct.ServeHTTP(w, req)
	})
}
