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

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletRequestWrapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Replays saved form data as a forwarded request, isolated from the login request's
 * parameters and Faces request-scoped attributes. Path elements are overridden because containers
 * may nest their forward wrapper beneath an earlier one (e.g. OmniFaces FacesViews), masking them.
 */
final class FormResubmitRequest extends HttpServletRequestWrapper {
    private static final List<String> DISPATCH_SCOPED_PREFIXES = List.of("jakarta.faces.", "com.sun.faces.",
            "org.apache.myfaces.", "org.omnifaces.", "jakarta.servlet.forward.", "jakarta.servlet.include.",
            FormResubmitSupport.FORM_IS_RESUBMITTED);
    private final String method;
    private final String path;
    private final String query;
    private final Map<String, String[]> parameters;
    private final Map<String, Object> attributes = new HashMap<>();

    FormResubmitRequest(HttpServletRequest request, String pathWithQuery, String method, String formData) {
        super(request);
        this.method = method;
        String[] pathAndQuery = pathWithQuery.split("\\?", 2);
        path = pathAndQuery[0];
        query = pathAndQuery.length == 2 ? pathAndQuery[1] : null;
        parameters = Arrays.stream(formData.split("&"))
                .filter(field -> !field.isEmpty())
                .map(field -> field.split("=", 2))
                .collect(Collectors.groupingBy(pair -> decode(pair[0]), LinkedHashMap::new,
                        Collectors.collectingAndThen(Collectors.mapping(pair -> pair.length == 2 ? decode(pair[1]) : "",
                                Collectors.toList()), values -> values.toArray(String[]::new))));
        Collections.list(request.getAttributeNames()).stream()
                .filter(name -> DISPATCH_SCOPED_PREFIXES.stream().noneMatch(name::startsWith))
                .forEach(name -> attributes.put(name, request.getAttribute(name)));
    }

    static boolean isResubmit(ServletRequest request) {
        return request instanceof FormResubmitRequest
                || request instanceof ServletRequestWrapper wrapper && wrapper.isWrapperFor(FormResubmitRequest.class);
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    @Override
    public String getMethod() {
        return method;
    }

    @Override
    public String getServletPath() {
        return path;
    }

    @Override
    public String getRequestURI() {
        return getContextPath() + path;
    }

    @Override
    public String getQueryString() {
        return query;
    }

    @Override
    public String getHeader(String name) {
        // Replays execute full-page actions. The caller translates their response for the original Ajax client.
        return "Faces-Request".equalsIgnoreCase(name) ? null : super.getHeader(name);
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return Collections.unmodifiableMap(parameters);
    }

    @Override
    public String getParameter(String name) {
        String[] values = parameters.get(name);
        return values == null ? null : values[0];
    }

    @Override
    public String[] getParameterValues(String name) {
        return parameters.get(name);
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(parameters.keySet());
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
            attributes.remove(name);
        } else {
            attributes.put(name, value);
        }
    }

    @Override
    public void removeAttribute(String name) {
        attributes.remove(name);
    }
}
