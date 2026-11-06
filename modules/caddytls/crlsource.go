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
	// defaultCRLMaxSize bounds what one source may return. Real CRLs
	// are at most a few megabytes.
	defaultCRLMaxSize = 64 << 20

	crlContentType = "application/pkix-crl"
)

var errCRLTooLarge = fmt.Errorf("larger than the %d byte limit", int64(defaultCRLMaxSize))

// crlSource is one configured place to obtain CRLs from.
type crlSource interface {
	// load returns the CRLs that parsed, a description of any CRL the
	// module refuses to read, and an error if nothing could be obtained.
	load(ctx context.Context, client *http.Client) (crls []*parsedCRL, refused []string, err error)

	// key is the location as configured, for use as a map key. It is
	// never logged, since a URL may carry credentials.
	key() string

	// display is the location with credentials hidden, for logs and errors.
	display() string
}

// crlFileSource is a CRL file on disk, in PEM or DER.
type crlFileSource string

func (s crlFileSource) key() string     { return string(s) }
func (s crlFileSource) display() string { return string(s) }

func (s crlFileSource) load(ctx context.Context, client *http.Client) ([]*parsedCRL, []string, error) {
	f, err := os.Open(string(s))
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	raw, err := readCapped(f)
	if err != nil {
		return nil, nil, err
	}
	crls, refused, err := parseCRLs(raw)
	return crls, refused, err
}

// crlURLSource is a CRL fetched over HTTP.
type crlURLSource string

func (s crlURLSource) key() string { return string(s) }

func (s crlURLSource) display() string { return redactURL(string(s)) }

// redact hides credentials in an error message, which Go's HTTP client
// may have quoted the URL into.
func (s crlURLSource) redact(err error) error {
	if err == nil {
		return nil
	}
	if redacted := redactURL(err.Error()); redacted != err.Error() {
		return errors.New(redacted)
	}
	return err
}

func (s crlURLSource) load(ctx context.Context, client *http.Client) ([]*parsedCRL, []string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, string(s), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", crlContentType)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, s.redact(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, s.redact(fmt.Errorf("got response status %s", resp.Status))
	}
	raw, err := readCapped(resp.Body)
	if err != nil {
		return nil, nil, s.redact(err)
	}
	crls, refused, err := parseCRLs(raw)
	return crls, refused, s.redact(err)
}

// crlURLCredentials matches the userinfo of a URL inside arbitrary text.
// It works on text rather than a parsed URL because the URL usually
// arrives already embedded in someone else's error message. Like Go, it
// splits the authority at the last @ before the first / ? # or space.
var crlURLCredentials = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://)[^\s/?#\[]*@`)

// redactURL hides the credentials of any URL in raw.
func redactURL(raw string) string {
	return crlURLCredentials.ReplaceAllString(raw, "${1}")
}

// readCapped reads r, refusing a body larger than defaultCRLMaxSize.
func readCapped(r io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, defaultCRLMaxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > defaultCRLMaxSize {
		return nil, errCRLTooLarge
	}
	return raw, nil
}
