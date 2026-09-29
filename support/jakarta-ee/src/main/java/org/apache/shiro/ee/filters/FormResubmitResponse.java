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
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import org.omnifaces.io.DefaultServletOutputStream;

/** Response isolation for the view-state GET and Ajax replays. Cookie attributes are preserved without rewriting. */
@SuppressWarnings("checkstyle:MethodCount")
final class FormResubmitResponse extends HttpServletResponseWrapper {
    private final ByteArrayOutputStream body = new ByteArrayOutputStream();
    private final Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private final List<Cookie> cookies = new ArrayList<>();
    private int status = SC_OK;
    private String encoding = StandardCharsets.UTF_8.name();
    private Locale locale = Locale.getDefault();
    private boolean committed;
    private ServletOutputStream output;
    private PrintWriter writer;

    FormResubmitResponse(HttpServletResponse response) {
        super(response);
    }

    @Override
    public ServletOutputStream getOutputStream() {
        if (writer != null) {
            throw new IllegalStateException("getWriter() has already been called");
        }
        if (output == null) {
            output = new DefaultServletOutputStream(body);
        }
        return output;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        if (output != null) {
            throw new IllegalStateException("getOutputStream() has already been called");
        }
        if (writer == null) {
            writer = new PrintWriter(new OutputStreamWriter(body, encoding));
        }
        return writer;
    }

    byte[] getBody() {
        if (writer != null) {
            writer.flush();
        }
        return body.toByteArray();
    }

    String getBodyAsString() throws IOException {
        return new String(getBody(), encoding);
    }

    void copyHeadersTo(HttpServletResponse response) {
        headers.forEach((name, values) -> {
            if (!"Set-Cookie".equalsIgnoreCase(name)) {
                response.setHeader(name, values.get(0));
                values.stream().skip(1).forEach(value -> response.addHeader(name, value));
            }
        });
    }

    void copyCookiesTo(HttpServletResponse response) {
        cookies.forEach(response::addCookie);
        getHeaders("Set-Cookie").forEach(value -> response.addHeader("Set-Cookie", value));
    }

    @Override
    public void addCookie(Cookie cookie) {
        if (!committed) {
            cookies.add(cookie);
        }
    }

    @Override
    public void flushBuffer() {
        getBody();
        committed = true;
    }

    @Override
    public boolean isCommitted() {
        return committed;
    }

    @Override
    public void resetBuffer() {
        if (committed) {
            throw new IllegalStateException("Response is committed");
        }
        getBody();
        body.reset();
    }

    @Override
    public void reset() {
        resetBuffer();
        headers.clear();
        cookies.clear();
        status = SC_OK;
        encoding = StandardCharsets.UTF_8.name();
        writer = null;
        output = null;
    }

    @Override
    public void setStatus(int value) {
        if (!committed) {
            status = value;
        }
    }

    @Override
    public int getStatus() {
        return status;
    }

    @Override
    public void sendError(int value) {
        sendError(value, null);
    }

    @Override
    public void sendError(int value, String message) {
        resetBuffer();
        status = value;
        committed = true;
    }

    @Override
    public void sendRedirect(String location) {
        sendRedirect(location, SC_FOUND, true);
    }

    @Override
    public void sendRedirect(String location, int value, boolean clearBuffer) {
        if (clearBuffer) {
            resetBuffer();
        }
        setStatus(value);
        setHeader("Location", location);
        committed = true;
    }

    @Override
    public void setHeader(String name, String value) {
        if (!committed) {
            if (value == null) {
                headers.remove(name);
            } else {
                headers.put(name, new ArrayList<>(List.of(value)));
            }
        }
    }

    @Override
    public void addHeader(String name, String value) {
        if (!committed && value != null) {
            headers.computeIfAbsent(name, key -> new ArrayList<>()).add(value);
        }
    }

    @Override
    public String getHeader(String name) {
        return headers.containsKey(name) ? headers.get(name).get(0) : null;
    }

    @Override
    public Collection<String> getHeaders(String name) {
        return List.copyOf(headers.getOrDefault(name, List.of()));
    }

    @Override
    public Collection<String> getHeaderNames() {
        return List.copyOf(headers.keySet());
    }

    @Override
    public boolean containsHeader(String name) {
        return headers.containsKey(name);
    }

    @Override
    public void setDateHeader(String name, long date) {
        setHeader(name, DateTimeFormatter.RFC_1123_DATE_TIME.format(Instant.ofEpochMilli(date).atZone(ZoneOffset.UTC)));
    }

    @Override
    public void addDateHeader(String name, long date) {
        addHeader(name, DateTimeFormatter.RFC_1123_DATE_TIME.format(Instant.ofEpochMilli(date).atZone(ZoneOffset.UTC)));
    }

    @Override
    public void setIntHeader(String name, int value) {
        setHeader(name, Integer.toString(value));
    }

    @Override
    public void addIntHeader(String name, int value) {
        addHeader(name, Integer.toString(value));
    }

    @Override
    public void setContentLength(int length) {
        setIntHeader("Content-Length", length);
    }

    @Override
    public void setContentLengthLong(long length) {
        setHeader("Content-Length", Long.toString(length));
    }

    @Override
    public void setContentType(String type) {
        setHeader("Content-Type", type);
        if (type != null) {
            for (String parameter : type.split(";")) {
                String[] pair = parameter.trim().split("=", 2);
                if (pair.length == 2 && "charset".equalsIgnoreCase(pair[0].trim())) {
                    setCharacterEncoding(pair[1].trim().replace("\"", ""));
                }
            }
        }
    }

    @Override
    public String getContentType() {
        return getHeader("Content-Type");
    }

    @Override
    public void setCharacterEncoding(String charset) {
        if (!committed && writer == null && charset != null) {
            encoding = charset;
        }
    }

    @Override
    public String getCharacterEncoding() {
        return encoding;
    }

    @Override
    public void setLocale(Locale value) {
        locale = value;
    }

    @Override
    public Locale getLocale() {
        return locale;
    }
}
