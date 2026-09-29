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

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletRequestWrapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.apache.shiro.ee.filters.FormResubmitSupport.FORM_IS_RESUBMITTED;
import static org.apache.shiro.ee.filters.FormResubmitSupport.MediaType.APPLICATION_FORM_URLENCODED;

/** A synchronous replay, without the login request's body or Faces request-scoped caches. */
@SuppressWarnings("checkstyle:MethodCount")
final class FormResubmitRequest extends HttpServletRequestWrapper {
    private static final List<String> DISPATCH_SCOPED_PREFIXES = List.of("jakarta.faces.", "com.sun.faces.",
            "org.apache.myfaces.", "org.omnifaces.", "jakarta.servlet.forward.", "jakarta.servlet.include.");
    private final String method;
    private final String path;
    private final String query;
    private final byte[] body;
    private final Map<String, String[]> parameters;
    private final Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private final Map<String, Object> attributes = new LinkedHashMap<>();
    private final ServletInputStream input;
    private BufferedReader reader;
    private boolean inputUsed;

    FormResubmitRequest(HttpServletRequest request, String pathWithQuery, String method, String formData) {
        super(request);
        this.method = method;
        int queryIndex = pathWithQuery.indexOf('?');
        path = queryIndex < 0 ? pathWithQuery : pathWithQuery.substring(0, queryIndex);
        query = queryIndex < 0 ? null : pathWithQuery.substring(queryIndex + 1);
        body = formData.getBytes(StandardCharsets.UTF_8);
        parameters = parseParameters(formData);
        headers.put(FORM_IS_RESUBMITTED, Boolean.TRUE.toString());
        headers.put("Content-Type", "POST".equals(method) ? APPLICATION_FORM_URLENCODED : null);
        headers.put("Content-Length", Integer.toString(body.length));
        headers.put("Transfer-Encoding", null);
        // Replays execute full-page actions. The caller translates their response for the original Ajax client.
        headers.put("Faces-Request", null);
        Collections.list(request.getAttributeNames()).stream()
                .filter(name -> DISPATCH_SCOPED_PREFIXES.stream().noneMatch(name::startsWith))
                .filter(name -> !name.equals(FORM_IS_RESUBMITTED))
                .forEach(name -> attributes.put(name, request.getAttribute(name)));
        var bytes = new ByteArrayInputStream(body);
        input = new ServletInputStream() {
            @Override
            public int read() {
                return bytes.read();
            }

            @Override
            public boolean isFinished() {
                return bytes.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener listener) {
                throw new IllegalStateException("Form replay only supports synchronous reads");
            }
        };
    }

    private static Map<String, String[]> parseParameters(String formData) {
        Map<String, List<String>> parsed = new LinkedHashMap<>();
        for (String field : formData.split("&")) {
            if (!field.isEmpty()) {
                String[] pair = field.split("=", 2);
                String name = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                String value = pair.length == 2 ? URLDecoder.decode(pair[1], StandardCharsets.UTF_8) : "";
                parsed.computeIfAbsent(name, key -> new ArrayList<>()).add(value);
            }
        }
        // The container merges the dispatch query ahead of these body parameters during forward().
        Map<String, String[]> result = new LinkedHashMap<>();
        parsed.forEach((name, values) -> result.put(name, values.toArray(String[]::new)));
        return result;
    }

    static boolean isResubmit(ServletRequest request) {
        while (request instanceof ServletRequestWrapper wrapper) {
            if (request instanceof FormResubmitRequest) {
                return true;
            }
            request = wrapper.getRequest();
        }
        return false;
    }

    @Override
    public String getMethod() {
        return method;
    }

    @Override
    public String getRequestURI() {
        return getContextPath() + path;
    }

    @Override
    public StringBuffer getRequestURL() {
        String originalURL = super.getRequestURL().toString();
        return new StringBuffer(originalURL.substring(0, originalURL.length() - super.getRequestURI().length()))
                .append(getRequestURI());
    }

    @Override
    public String getServletPath() {
        return path;
    }

    @Override
    public String getPathInfo() {
        return null;
    }

    @Override
    public String getQueryString() {
        return query;
    }

    @Override
    public String getContentType() {
        return getHeader("Content-Type");
    }

    @Override
    public int getContentLength() {
        return body.length;
    }

    @Override
    public long getContentLengthLong() {
        return body.length;
    }

    @Override
    public String getCharacterEncoding() {
        return StandardCharsets.UTF_8.name();
    }

    @Override
    public ServletInputStream getInputStream() {
        if (reader != null) {
            throw new IllegalStateException("getReader() has already been called");
        }
        inputUsed = true;
        return input;
    }

    @Override
    public BufferedReader getReader() {
        if (inputUsed) {
            throw new IllegalStateException("getInputStream() has already been called");
        }
        if (reader == null) {
            reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        }
        return reader;
    }

    @Override
    public String getParameter(String name) {
        String[] values = parameters.get(name);
        return values == null ? null : values[0];
    }

    @Override
    public String[] getParameterValues(String name) {
        String[] values = parameters.get(name);
        return values == null ? null : values.clone();
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(parameters.keySet());
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        Map<String, String[]> copy = new LinkedHashMap<>();
        parameters.forEach((name, values) -> copy.put(name, values.clone()));
        return Collections.unmodifiableMap(copy);
    }

    @Override
    public String getHeader(String name) {
        return headers.containsKey(name) ? headers.get(name) : super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        if (!headers.containsKey(name)) {
            return super.getHeaders(name);
        }
        String value = headers.get(name);
        return Collections.enumeration(value == null ? Collections.emptyList() : Collections.singletonList(value));
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        var names = new java.util.TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        names.addAll(Collections.list(super.getHeaderNames()));
        headers.forEach((name, value) -> {
            if (value == null) {
                names.remove(name);
            } else {
                names.add(name);
            }
        });
        return Collections.enumeration(names);
    }

    @Override
    public int getIntHeader(String name) {
        String value = getHeader(name);
        return value == null ? -1 : Integer.parseInt(value);
    }

    @Override
    public Object getAttribute(String name) {
        return attributes.get(name);
    }

    @Override
    public Enumeration<String> getAttributeNames() {
        return Collections.enumeration(attributes.keySet());
    }

    @Override
    public void setAttribute(String name, Object value) {
        if (value == null) {
            removeAttribute(name);
        } else {
            attributes.put(name, value);
        }
    }

    @Override
    public void removeAttribute(String name) {
        attributes.remove(name);
    }
}
