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
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import lombok.experimental.Delegate;
import org.apache.shiro.ee.filters.FormResubmitSupport.AjaxReplay;
import org.apache.shiro.web.util.WebUtils;
import org.omnifaces.filter.MutableRequestFilter.MutableRequest;

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
    private static final String FACES_REQUEST_HEADER = "Faces-Request";
    private final @Getter String method;
    private final AjaxReplay ajaxReplay;
    private final @Delegate(types = Parameters.class) MutableRequest parameters;
    private final Map<String, Object> attributes = new HashMap<>();

    @SuppressWarnings("unused")
    private interface Parameters {
        String getParameter(String name);
        String[] getParameterValues(String name);
        Enumeration<String> getParameterNames();
        Map<String, String[]> getParameterMap();
    }

    FormResubmitRequest(HttpServletRequest request, String method, Map<String, List<String>> formFields,
            AjaxReplay ajaxReplay) {
        super(unwrap(request));
        this.method = method;
        this.ajaxReplay = ajaxReplay;
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
        // isWrapperFor() inspects only the wrapped chain, not the wrapper itself
        return request instanceof FormResubmitRequest
                || request instanceof ServletRequestWrapper wrapper && wrapper.isWrapperFor(FormResubmitRequest.class);
    }

    private static HttpServletRequest unwrap(HttpServletRequest request) {
        return request instanceof ServletRequestWrapper wrapper ? unwrap(WebUtils.toHttp(wrapper.getRequest())) : request;
    }

    /**
     * A full-page replay's response is translated for the original Ajax client by the caller,
     * so the target must not see the Ajax header through any accessor
     */
    private boolean isHidden(String header) {
        return !ajaxReplay.isPassThrough() && FACES_REQUEST_HEADER.equalsIgnoreCase(header);
    }

    @Override
    public String getHeader(String name) {
        return isHidden(name) ? null : super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        return isHidden(name) ? Collections.emptyEnumeration() : super.getHeaders(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        return Collections.enumeration(Collections.list(super.getHeaderNames()).stream()
                .filter(name -> !isHidden(name)).toList());
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
