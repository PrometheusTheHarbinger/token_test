package main

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/kataras/iris/v12/httptest"
)

func TestTokenGeneration(t *testing.T) {
	app := prepareApp()
	e := httptest.New(t, app)
	e.Request("GET", "/").WithURL("/?GUID=a").Expect().JSON()
}

func TestTokenRefresh(t *testing.T) {
	app := prepareApp()
	e := httptest.New(t, app)
	token := e.Request("GET", "/").WithURL("/?GUID=a").Expect().JSON().Object().Value("refresh_token").String().Raw()
	e.Request("GET", "/").WithURL(fmt.Sprintf("/refresh?GUID=a&refresh=%s", token)).Expect().JSON()
}

func TestBadRefreshToken(t *testing.T) {
	app := prepareApp()
	e := httptest.New(t, app)
	e.Request("GET", "/").WithURL(fmt.Sprintf("/refresh?GUID=a&refresh=%s", "lorem_ipsum")).Expect().Status(http.StatusUnauthorized)
}

func TestCorrectTokenWithWrongGUID(t *testing.T) {
	app := prepareApp()
	e := httptest.New(t, app)
	token := e.Request("GET", "/").WithURL("/?GUID=a").Expect().JSON().Object().Value("refresh_token").String().Raw()
	e.Request("GET", "/").WithURL(fmt.Sprintf("/refresh?GUID=ab&refresh=%s", token)).Expect().Status(http.StatusUnauthorized)
}

func TestSendEmail(t *testing.T) {
	if SendWarningEmail() != nil {
		panic("No email sent!")
	}
}
