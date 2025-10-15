package mdlv

import (
	"net/http"

	"github.com/chains-lab/ape"
	"github.com/chains-lab/ape/problems"
	"github.com/chains-lab/restkit/token"
	"github.com/google/uuid"
)

func CompanyGrant(ctxKey interface{}, CompanyID uuid.UUID, allowedCompanyRoles map[string]bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			user, ok := ctx.Value(ctxKey).(token.UserData)
			if !ok {
				ape.RenderErr(w, problems.Unauthorized("Missing AuthorizationHeader header"))
				return
			}

			if user.CompanyID == nil || *user.CompanyID != CompanyID {
				ape.RenderErr(w, problems.Forbidden("user company ID does not match"))
				return
			}

			if user.CompanyID == nil || !allowedCompanyRoles[*user.CompanyRole] {
				ape.RenderErr(w, problems.Forbidden("user company role not allowed"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
