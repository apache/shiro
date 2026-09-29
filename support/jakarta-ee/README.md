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
before the POST. Remembered Ajax submissions retain the two-POST flow, buffering
intermediate responses. A calling Faces context is restored after each dispatch.
The successful POST's cookies are preserved unchanged; the expired-view probe
must not replace its flash cookie and lose submitted-form messages.

## Application filter configuration

Shiro's Jakarta EE filter is mapped to `DispatcherType.FORWARD`, so the forwarded
target's security chain runs again. Application filters needed during replay
must also be mapped to `FORWARD`, not only `REQUEST`. Leave Shiro's
`filterOncePerRequest` disabled when using form resubmission.

Replay remains in the same servlet request lifecycle. Application filters and
request-scoped components should not assume that a replay starts a new external
request. Saved targets must be within the current context; servlet-private
`WEB-INF` and `META-INF` resources cannot be replay targets.

The old `org.apache.shiro.form-resubmit-host`,
`org.apache.shiro.form-resubmit-port`, and form-resubmit blacklist settings are
no longer used. Saved-form cookies still use the existing secure-cookie setting;
there is no separate replay cookie jar or cookie-header rewriting.
