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

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import org.omnifaces.io.DefaultServletOutputStream;

/**
 * Buffers a replay's body, status and redirect instead of committing them to the browser.
 * Other headers and cookies pass through, unless cookies are being discarded.
 */
final class FormResubmitResponse extends HttpServletResponseWrapper {
    private final ByteArrayOutputStream body = new ByteArrayOutputStream();
    private final boolean keepCookies;
    private int status = SC_OK;
    private PrintWriter writer;

    FormResubmitResponse(HttpServletResponse response, boolean keepCookies) {
        super(response);
        this.keepCookies = keepCookies;
    }

    byte[] getBody() {
        if (writer != null) {
            writer.flush();
        }
        return body.toByteArray();
    }

    String getBodyAsString() throws IOException {
        return new String(getBody(), getCharacterEncoding());
    }

    @Override
    public ServletOutputStream getOutputStream() {
        return new DefaultServletOutputStream(body);
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        if (writer == null) {
            writer = new PrintWriter(new OutputStreamWriter(body, getCharacterEncoding()));
        }
        return writer;
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
        sendError(status, null);
    }

    @Override
    public void sendError(int status, String message) {
        resetBuffer();
        this.status = status;
    }

    @Override
    public void sendRedirect(String location) {
        sendRedirect(location, SC_FOUND, true);
    }

    @Override
    public void sendRedirect(String location, int status, boolean clearBuffer) {
        if (clearBuffer) {
            resetBuffer();
        }
        this.status = status;
        super.setHeader("Location", location);
    }

    @Override
    public void addCookie(Cookie cookie) {
        if (keepCookies) {
            super.addCookie(cookie);
        }
    }

    @Override
    public void setHeader(String name, String value) {
        if (isPassedThrough(name)) {
            super.setHeader(name, value);
        }
    }

    @Override
    public void addHeader(String name, String value) {
        if (isPassedThrough(name)) {
            super.addHeader(name, value);
        }
    }

    private boolean isPassedThrough(String name) {
        return !"Content-Length".equalsIgnoreCase(name) && (keepCookies || !"Set-Cookie".equalsIgnoreCase(name));
    }

    @Override
    public void setContentLength(int len) {
    }

    @Override
    public void setContentLengthLong(long len) {
    }

    @Override
    public void flushBuffer() {
    }

    @Override
    public boolean isCommitted() {
        return false;
    }

    @Override
    public void resetBuffer() {
        getBody();
        body.reset();
    }

    @Override
    public void reset() {
        resetBuffer();
        status = SC_OK;
    }
}
