package httpcap

import (
	"bytes"
	"net/http"
	"testing"

	"io/ioutil"

	"github.com/stretchr/testify/assert"
)

func TestEnvelop(t *testing.T) {
	b := bytes.NewBufferString("payload-stuff")
	r, err := http.NewRequest("POST", "/foobar/hello/baz.html?query=nice", b)
	assert.NoError(t, err)

	//r.AddCookie(&http.Cookie{Name: "session_id", Value: "Super secret", Expires: time.Now().Add(time.Hour * 24 * 365)})
	r.Header.Add("Encoding", "urlencoded")
	r.Header.Add("Charset", "utf8")

	e, err := Envelop("PUT", "/requests?a=1", r)
	assert.NoError(t, err)

	body, err := ioutil.ReadAll(e.Body)
	assert.NoError(t, err)

	expectPayload := "POST /foobar/hello/baz.html?query=nice HTTP/1.1\r\nCharset: utf8\r\nEncoding: urlencoded\r\n\r\npayload-stuff"

	assert.Equal(t, expectPayload, string(body))
	assert.Equal(t, EnvelopContentType, e.Header.Get("Content-Type"))
}

func TestReadEnvelop(t *testing.T) {
	b := bytes.NewBufferString("payload-stuff")
	payloadBytes := b.Bytes()
	r, err := http.NewRequest("POST", "/foobar/hello/baz.html?query=nice", b)
	assert.NoError(t, err)

	r.Header.Add("Encoding", "urlencoded")
	r.Header.Add("Charset", "utf8")

	e, err := Envelop("GET", "/requests?a=1", r)
	assert.NoError(t, err)

	ec, err := ReadEnvelop(e.Body)
	assert.NoError(t, err)
	defer e.Body.Close()

	body, err := ioutil.ReadAll(ec.Body)
	assert.NoError(t, err)
	defer ec.Body.Close()

	assert.Equal(t, payloadBytes, body)
	assert.Equal(t, r.Method, ec.Method)
	assert.EqualValues(t, r.URL, ec.URL)
	assert.EqualValues(t, r.Header, ec.Header)
	assert.Equal(t, r.Proto, ec.Proto)
}
