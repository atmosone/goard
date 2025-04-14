package goard

import "net/http"

type cookiesContainer struct {
	name string
}

func (c *cookiesContainer) SetSession(w http.ResponseWriter, s *Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.name,
		Value:    s.id,
		HttpOnly: true,
		Expires:  s.exp,
	})
}

func (c *cookiesContainer) GetSession(r *http.Request) string {
	cookie, err := r.Cookie(c.name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func NewCookiesContainer(name string) Container {
	return &cookiesContainer{
		name: name,
	}
}
