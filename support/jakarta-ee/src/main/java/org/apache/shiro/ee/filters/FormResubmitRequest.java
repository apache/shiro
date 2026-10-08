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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import lombok.experimental.Delegate;
import org.omnifaces.filter.MutableRequestFilter.MutableRequest;
import org.omnifaces.util.Utils;

/**
 * Replays saved form data in place of the login request's parameters, with a private request scope
 * (attributes), so that Faces and CDI request state doesn't leak between replays and the login request.
 * Wraps the container's own request, so that the forward supplies the target's paths
 * beneath application wrappers (e.g. OmniFaces FacesViews) that would otherwise mask them.
 */
final class FormResubmitRequest extends HttpServletRequestWrapper {
    private static final List<String> DISPATCH_SCOPED_PREFIXES = List.of("jakarta.faces.", "com.sun.faces.",
            "org.apache.myfaces.", "org.omnifaces.", "jakarta.servlet.forward.", "jakarta.servlet.include.",
            FormResubmitSupport.FORM_IS_RESUBMITTED);
    private final @Getter String method;
    private final @Delegate(types = Parameters.class) MutableRequest parameters;
    private final Map<String, Object> attributes = new HashMap<>();

    @SuppressWarnings("unused")
    private interface Parameters {
        String getParameter(String name);
        String[] getParameterValues(String name);
        Enumeration<String> getParameterNames();
        Map<String, String[]> getParameterMap();
    }

    FormResubmitRequest(HttpServletRequest request, String method, String formData) {
        super(unwrap(request));
        this.method = method;
        var formFields = toFormFields(formData);
        parameters = new MutableRequest(request) {
            @Override
            public Map<String, List<String>> getMutableParameterMap() {
                return formFields;
            }
        };
        Collections.list(request.getAttributeNames()).stream()
                .filter(name -> DISPATCH_SCOPED_PREFIXES.stream().noneMatch(name::startsWith))
                .forEach(name -> attributes.put(name, request.getAttribute(name)));
    }

    static boolean isResubmit(ServletRequest request) {
        return request instanceof ServletRequestWrapper wrapper && wrapper.isWrapperFor(FormResubmitRequest.class);
    }

    private static Map<String, List<String>> toFormFields(String formData) {
        var parsed = new LinkedHashMap<String, List<String>>();
        for (String field : formData.split("&")) {
            if (!field.isEmpty()) {
                String[] pair = field.split("=", 2);
                parsed.computeIfAbsent(Utils.decodeURL(pair[0]), name -> new ArrayList<>())
                        .add(pair.length == 2 ? Utils.decodeURL(pair[1]) : "");
            }
        }
        return parsed;
    }

    private static HttpServletRequest unwrap(HttpServletRequest request) {
        return request instanceof ServletRequestWrapper wrapper ? unwrap((HttpServletRequest) wrapper.getRequest()) : request;
    }

    @Override
    public String getHeader(String name) {
        // Replays execute full-page actions. The caller translates their response for the original Ajax client.
        return "Faces-Request".equalsIgnoreCase(name) ? null : super.getHeader(name);
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
