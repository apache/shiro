/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.ee.filters;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.omnifaces.servlet.BufferedHttpServletResponse;

/**
 * Buffers a replay's body and captures its status instead of committing them to the browser.
 * Other headers and cookies pass through, unless cookies are being discarded.
 */
final class FormResubmitResponse extends BufferedHttpServletResponse {
    private final boolean keepCookies;
    private int status = SC_OK;

    FormResubmitResponse(HttpServletResponse response, boolean keepCookies) {
        super(response);
        this.keepCookies = keepCookies;
    }

    @Override
    public int getStatus() {
        return status;
    }

    @Override
    public void setStatus(int status) {
        this.status = status;
    }

    @Override
    public void sendError(int status) {
        setStatus(status);
    }

    @Override
    public void sendError(int status, String message) {
        setStatus(status);
    }

    @Override
    public void sendRedirect(String location) {
        setStatus(SC_FOUND);
        setHeader("Location", location);
    }

    @Override
    public void addCookie(Cookie cookie) {
        if (keepCookies) {
            super.addCookie(cookie);
        }
    }

    @Override
    public void flushBuffer() {
    }

    @Override
    public void setContentLength(int len) {
    }

    @Override
    public void setContentLengthLong(long len) {
    }
}
