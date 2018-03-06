// Copyright 2015 Google Inc. All Rights Reserved.
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

package httputil

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
)

// Wrap the supplied round tripper in a layer that dumps information about HTTP
// requests. unmodified.
func EncryptionHeadersRoundTripper(
	in CancellableRoundTripper,
	key []byte) (out CancellableRoundTripper) {

	h := sha256.New()
	h.Write(key)

	out = &encryptionHeadersRoundTripper{
		wrapped: in,
		keyalgo: "AES256",
		keyhash: base64.StdEncoding.EncodeToString(h.Sum(nil)),
		key:     base64.StdEncoding.EncodeToString(key),
	}

	return
}

////////////////////////////////////////////////////////////////////////
// debuggingRoundTripper
////////////////////////////////////////////////////////////////////////

type encryptionHeadersRoundTripper struct {
	wrapped CancellableRoundTripper
	keyalgo string
	keyhash string
	key     string
}

func (t *encryptionHeadersRoundTripper) RoundTrip(
	req *http.Request) (resp *http.Response, err error) {

	req.Header.Add("x-goog-encryption-algorithm", t.keyalgo)
	req.Header.Add("x-goog-encryption-key", t.key)
	req.Header.Add("x-goog-encryption-key-sha256", t.keyhash)

	// Execute the request.
	resp, err = t.wrapped.RoundTrip(req)
	if err != nil {
		return
	}

	return
}

func (t *encryptionHeadersRoundTripper) CancelRequest(req *http.Request) {
	t.wrapped.CancelRequest(req)
}
