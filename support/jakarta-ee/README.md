<!--
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Jakarta EE form resubmission

Saved forms are replayed within the current web application using
`RequestDispatcher.forward`, without an outbound HTTP connection. The replay
uses the current Shiro subject, session, and browser response. Its request body
and form parameters replace those of the login request.

For server-side Faces state saving, a buffered GET obtains a new view state
before the POST. A calling Faces context is restored after each dispatch.

Each replay's status, headers, cookies and body are captured rather than written
to the browser response, which is also shielded from `reset()`, `resetBuffer()`
and `flushBuffer()`. Only a successful replay is applied, with its headers and
cookies. View-state GETs and failed attempts leave the login request's response,
such as its session cookies, untouched. Saved form data is decoded with the
request's character encoding, falling back to the servlet context's and then UTF-8.

A remembered subject's Faces Ajax submission, replayed in place when its
session is gone, stays an Ajax request:
the saved partial request is replayed with the refreshed view state, and its
partial response is passed through to the waiting Ajax client, without a full
page refresh. Since the server-side view is rebuilt from scratch, the replay
renders the whole view (`@all`) by default, which resynchronizes the page and
the view state of all its forms with the server. Set the
`org.apache.shiro.form-resubmit.ajax-render-all.disabled` context parameter to
`true` to keep the form's own render targets instead; components outside them
then keep their pre-expiry client state, and with Mojarra, other forms on the
page keep their expired view state. A partial response that reports an
unhandled Faces error is treated as a failed replay and falls back to a redirect
to the saved request, as a failed full-page replay does. After a login flow,
the browser is on the login page instead, so the submission is replayed as a
full-page action and the browser is redirected to the saved request.

## Application filter configuration

Shiro's Jakarta EE filter is mapped to `DispatcherType.FORWARD`, so the forwarded
target's security chain runs again. Application filters needed during replay
must also be mapped to `FORWARD`, not only `REQUEST`. Leave Shiro's
`filterOncePerRequest` disabled when using form resubmission.

Replay remains in the same servlet request lifecycle. Application filters and
request-scoped components should not assume that a replay starts a new external
request. Saved targets must be within the current context; servlet-private
`WEB-INF` and `META-INF` resources cannot be replay targets.

Resubmission is best-effort. Replays are buffered, so if the forward fails or
the target doesn't answer with `200` or `302`, the fault is logged and the user
is simply redirected to the saved request without the form being resubmitted.

The old `org.apache.shiro.form-resubmit-host`,
`org.apache.shiro.form-resubmit-port`, and form-resubmit blacklist settings are
no longer used. Saved-form cookies still use the existing secure-cookie setting;
there is no separate replay cookie jar or cookie-header rewriting.
