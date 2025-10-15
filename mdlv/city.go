package mdlv

import (
	"net/http"

	"github.com/chains-lab/ape"
	"github.com/chains-lab/ape/problems"
	"github.com/chains-lab/restkit/token"
	"github.com/google/uuid"
)

func CityGrant(ctxKey interface{}, cityID uuid.UUID, allowedCityRoles map[string]bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			user, ok := ctx.Value(ctxKey).(token.UserData)
			if !ok {
				ape.RenderErr(w, problems.Unauthorized("Missing AuthorizationHeader header"))
				return
			}

			if user.CityID == nil || *user.CityID != cityID {
				ape.RenderErr(w, problems.Forbidden("user city ID does not match"))
				return
			}

			if user.CityRole == nil || !allowedCityRoles[*user.CityRole] {
				ape.RenderErr(w, problems.Forbidden("user city role not allowed"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
