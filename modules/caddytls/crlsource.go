// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddytls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
)

const (
	// defaultCRLMaxSize bounds how much memory one misbehaving distribution point can
	// consume. A private CA's list of client certificates is a few kilobytes, and even a public CA
	// revoking at length stays under a megabyte or two; this is generous by orders of magnitude.
	defaultCRLMaxSize = 64 << 20
)

// crlSource is one configured place a CRL can be obtained from.
type crlSource struct {
	kind     string // "file" or "url"
	location string
}

// display returns the source as it should appear in a log line or an error message. A
// distribution point may be behind basic auth, and its credentials are not something to write into
// a log file which is often shipped somewhere else.
func (cs crlSource) display() string {
	if cs.kind != "url" {
		return cs.location
	}
	return redactURL(cs.location)
}

// crlURLCredentials matches the credentials of a URL inside arbitrary text. Both halves go: the
// username is half a credential too, and on a PKI which serves several tenants it may be the part
// worth keeping to oneself.
//
// This works on the rendered string rather than on a parsed URL because most of what needs
// redacting is not ours: an error quoting the URL it was about arrives already formatted by
// whoever wrote it, and a URL which does not parse still carries its password.
//
// The run being removed may itself contain an @, since a password with an unescaped one in it is
// what net/url calls userinfo too — Go splits authority at the last @, so this does the same and
// cannot leave the tail of a secret behind. It stops at the first / ? # or space, which is where
// an authority ends, so an @ in a path is left alone: there is nothing before it in that token
// which could be read as credentials.
var crlURLCredentials = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://)[^\s/?#\[]*@`)

// redactURL hides the credentials of a URL, leaving everything an operator needs to identify it.
func redactURL(raw string) string {
	return crlURLCredentials.ReplaceAllString(raw, "${1}")
}

// redactErr strips credentials out of an error about a URL, which quotes the URL it was about.
// The whole message is rewritten rather than the configured URL searched for and replaced, because
// the text is not ours to control: Go's http client masks only the password (so the configured
// string never appears verbatim), and a redirect or a TLS error may render the URL differently
// again. Anything which looks like credentials in it goes, whichever form it arrived in.
func (cs crlSource) redactErr(err error) error {
	if err == nil || cs.kind != "url" {
		return err
	}
	msg := err.Error()
	if redacted := redactURL(msg); redacted != msg {
		return errors.New(redacted)
	}
	return err
}

// load reads and parses every CRL at the source.
func (cs crlSource) load(ctx context.Context, client *http.Client) ([]*parsedCRL, []string, error) {
	var raw []byte
	var err error
	switch cs.kind {
	case "file":
		raw, err = readFileCapped(cs.location)
	case "url":
		raw, err = readURL(ctx, client, cs.location)
	default:
		// buildSources constructs only the two kinds above, so this is unreachable today. It
		// refuses rather than reading a file, which is what falling through would otherwise invite
		// a third kind to do by accident.
		return nil, nil, fmt.Errorf("unknown CRL source kind '%s'", cs.kind)
	}
	if err != nil {
		return nil, nil, cs.redactErr(err)
	}
	crls, refused, err := parseCRLs(raw)
	return crls, refused, cs.redactErr(err)
}

// readFileCapped reads a CRL from disk.
func readFileCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readCapped(f, "file")
}

// readURL fetches a CRL over HTTP.
func readURL(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/pkix-crl")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("got non-2xx status code %d", resp.StatusCode)
	}
	return readCapped(resp.Body, "response")
}

// readCapped reads a CRL body, refusing one longer than defaultCRLMaxSize rather than holding it.
// A distribution point is somebody else's web server, and an unbounded read there is a way to run
// this process out of memory.
func readCapped(r io.Reader, what string) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, defaultCRLMaxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > defaultCRLMaxSize {
		return nil, fmt.Errorf("%s is larger than the maximum of %d bytes", what, int64(defaultCRLMaxSize))
	}
	return raw, nil
}
