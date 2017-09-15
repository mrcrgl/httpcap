package httpcap

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
)

const newLine = "\r\n"
const headerTemplate = `%s %s %s%s`

const EnvelopContentType = "http/request"

var _ io.ReadCloser = &pullStream{}

type pullStream struct {
	header        []byte
	headerWritten bool
	readCloser    io.ReadCloser
}

func (ps *pullStream) Read(p []byte) (n int, err error) {
	if !ps.headerWritten {
		n := copy(p, ps.header)
		ps.headerWritten = true
		return n, nil
	}

	return ps.readCloser.Read(p)
}

func (ps *pullStream) Close() error {
	return ps.readCloser.Close()
}

var _ io.ReadCloser = &body{}

type body struct {
	r io.Reader
}

func (b *body) Read(p []byte) (n int, err error) {
	return b.r.Read(p)
}

func (_ *body) Close() error {
	return nil
}

func Envelop(method, url string, r *http.Request) (*http.Request, error) {
	body := Payload(r)

	envelop, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	envelop.WithContext(r.Context())

	envelop.Header.Add("Content-Type", EnvelopContentType)

	r.Cookies()

	return envelop, nil
}

func ReadEnvelop(b io.Reader) (req *http.Request, err error) {
	req = new(http.Request)
	rt := textproto.NewReader(bufio.NewReader(b))

	var s string
	if s, err = rt.ReadLine(); err != nil {
		return
	}

	var ok bool
	req.Method, req.RequestURI, req.Proto, ok = parseRequestLine(s)
	if !ok {
		return req, fmt.Errorf("malformed HTTP request: [%s]", s)
	}
	/*if !validMethod(req.Method) {
		return nil, errors.New("invalid method")
	}*/
	rawurl := req.RequestURI
	if req.ProtoMajor, req.ProtoMinor, ok = http.ParseHTTPVersion(req.Proto); !ok {
		return req, fmt.Errorf("malformed HTTP version: [%s]", req.Proto)
	}

	if req.URL, err = url.ParseRequestURI(rawurl); err != nil {
		return req, err
	}

	// Subsequent lines: Key: value.
	mimeHeader, err := rt.ReadMIMEHeader()
	if err != nil {
		return req, err
	}
	req.Header = http.Header(mimeHeader)

	req.Body = &body{rt.R}
	req.Close = false

	return
}

func parseRequestLine(line string) (method, requestURI, proto string, ok bool) {
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return line[:s1], line[s1+1 : s2], line[s2+1:], true
}

func Payload(r *http.Request) io.ReadCloser {
	ps := &pullStream{
		header:     header(r).Bytes(),
		readCloser: r.Body,
	}

	return ps
}

func header(r *http.Request) *bytes.Buffer {
	b := bytes.NewBufferString(fmt.Sprintf(headerTemplate, r.Method, r.URL.RequestURI(), r.Proto, newLine))

	r.Header.Write(b)

	b.WriteString(newLine)

	return b
}
