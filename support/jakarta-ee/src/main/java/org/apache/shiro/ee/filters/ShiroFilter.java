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

import static org.apache.shiro.ee.cdi.ShiroScopeContext.addScopeSessionListeners;
import static org.apache.shiro.ee.filters.FormResubmitSupport.FORM_IS_RESUBMITTED;
import static org.apache.shiro.ee.filters.FormResubmitSupport.getPostData;
import static org.apache.shiro.ee.filters.FormResubmitSupport.isJSFClientStateSavingMethod;
import static org.apache.shiro.ee.filters.FormResubmitSupport.isPostRequest;
import static org.apache.shiro.ee.filters.FormResubmitSupport.resubmitSavedForm;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.DONT_ADD_ANY_MORE_COOKIES;
import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.getCharacterEncoding;
import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.isCharEncodingEnabled;
import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.isShiroEEDisabled;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.Principal;
import java.util.Optional;
import java.util.regex.Pattern;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.experimental.Delegate;
import lombok.extern.slf4j.Slf4j;
import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.isServletNoPrincipal;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.isShiroEERedirectDisabled;
import static org.apache.shiro.web.filter.authz.SslFilter.HTTPS_SCHEME;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.session.mgt.WebSessionKey;
import org.apache.shiro.web.subject.WebSubjectContext;
import org.apache.shiro.web.util.WebUtils;
import org.omnifaces.util.Servlets;
import org.omnifaces.util.Utils;

/**
 * Stops JEE server from interpreting Shiro principal as direct EJB principal,
 * this has sideffects of trying to log in to remote EJBs with the credentials from Shiro,
 * which isn't what this meant to do, as it's meant to just transfer Shiro credentials
 * to remote EJB call site.
 *
 * Thus, force null EJB principal for the web session,
 * as the real principal comes from the EjbSecurityFilter's doAs() call
 *
 * Also handles X-Forwarded-Proto support
 */
@Slf4j
@WebFilter(filterName = "ShiroFilter", urlPatterns = "/*",
        dispatcherTypes = { DispatcherType.ERROR, DispatcherType.FORWARD,
            DispatcherType.INCLUDE, DispatcherType.REQUEST,
            DispatcherType.ASYNC }, asyncSupported = true)
public class ShiroFilter extends org.apache.shiro.web.servlet.ShiroFilter {
    private static final String X_FORWARDED_PROTO = "X-Forwarded-Proto";
    private static final Pattern HTTP_TO_HTTPS = Pattern.compile("^\\s*http(.*)");

    private static class WrappedRequest extends ShiroHttpServletRequest {
        @Getter(value = AccessLevel.PRIVATE, lazy = true)
        private final boolean httpsNeeded = createHttpButNeedHttps();
        @Getter(value = AccessLevel.PRIVATE, lazy = true)
        private final StringBuffer secureRequestURL = httpsRequestURL();

        WrappedRequest(HttpServletRequest wrapped, ServletContext servletContext, boolean httpSessions) {
            super(wrapped, servletContext, httpSessions);
        }

        @Override
        public Principal getUserPrincipal() {
            if (isServletNoPrincipal(servletContext)) {
                return null;
            } else {
                return super.getUserPrincipal();
            }
        }

        @Override
        public String getScheme() {
            if (isHttpsNeeded()) {
                return HTTPS_SCHEME;
            } else {
                return super.getScheme();
            }
        }

        @Override
        public StringBuffer getRequestURL() {
            if (isHttpsNeeded()) {
                return getSecureRequestURL();
            } else {
                return super.getRequestURL();
            }
        }

        @Override
        public boolean isSecure() {
            return super.isSecure() || isHttpsNeeded();
        }

        private boolean createHttpButNeedHttps() {
            return !HTTPS_SCHEME.equalsIgnoreCase(super.getScheme())
                    && HTTPS_SCHEME.equalsIgnoreCase(WebUtils.toHttp(getRequest())
                            .getHeader(X_FORWARDED_PROTO));
        }

        private StringBuffer httpsRequestURL() {
            return new StringBuffer(HTTP_TO_HTTPS.matcher(super.getRequestURL())
                    .replaceFirst(HTTPS_SCHEME + "$1"));
        }
    }

    private static class WrappedResponse extends HttpServletResponseWrapper {
        private final ServletRequest request;

        WrappedResponse(HttpServletResponse response, ServletRequest request) {
            super(response);
            this.request = request;
        }

        @Override
        public void addCookie(Cookie cookie) {
            if (request.getAttribute(DONT_ADD_ANY_MORE_COOKIES) != Boolean.TRUE) {
                super.addCookie(cookie);
            }
        }

        @Override
        public void sendRedirect(String location) throws IOException {
            if (!Utils.startsWithOneOf(location, "http://", "https://")
                    && !isShiroEERedirectDisabled(request.getServletContext())) {
                location = Servlets.getRequestDomainURL(WebUtils.toHttp(request)) + location;
            }
            super.sendRedirect(location);
        }
    }

    @RequiredArgsConstructor
    static class WrappedSecurityManager implements WebSecurityManager, org.apache.shiro.mgt.WrappedSecurityManager {
        final @Delegate WebSecurityManager wrapped;

        @Override
        public Subject createSubject(SubjectContext context) {
            if (context instanceof WebSubjectContext webContext && wrapped instanceof DefaultSecurityManager) {
                DefaultWebSecurityManager wsm = (DefaultWebSecurityManager) wrapped;
                Session session = null;
                try {
                    session = wsm.getSession(new WebSessionKey(webContext.getSessionId(), webContext.getServletRequest(),
                            webContext.getServletResponse()));
                } catch (SessionException e) {
                    log.debug("Create Session Failed", e);
                }
                var newSubject = wrapped.createSubject(context);
                if (newSubject.isRemembered() && session == null
                        && !isJSFClientStateSavingMethod(webContext.getServletRequest().getServletContext())) {
                    log.debug("Remembered Subject with new session {}", newSubject.getPrincipal());
                    webContext.getServletRequest().setAttribute(FORM_IS_RESUBMITTED, Boolean.TRUE);
                }
                return newSubject;
            } else {
                return wrapped.createSubject(context);
            }
        }

        @Override
        @SuppressWarnings("unchecked")
        public <SM extends SecurityManager> SM unwrap() {
            return (SM) wrapped;
        }
    }

    @Override
    protected ServletRequest wrapServletRequest(HttpServletRequest request) {
        if (isShiroEEDisabled(request.getServletContext())) {
            return super.wrapServletRequest(request);
        } else {
            return new WrappedRequest(request, getServletContext(), isHttpSessions());
        }
    }

    @Override
    // wrapServletResponse() only gets called in certain configurations, we need to wrap them all
    protected ServletResponse prepareServletResponse(ServletRequest request, ServletResponse response, FilterChain chain) {
        if (isShiroEEDisabled(request.getServletContext()) || !(request instanceof HttpServletRequest)) {
            return super.prepareServletResponse(request, response, chain);
        } else {
            return new WrappedResponse(WebUtils.toHttp(response), request);
        }
    }

    @Override
    public void init() throws Exception {
        if (isShiroEEDisabled(getServletContext())) {
            return;
        }
        super.init();
        try {
            addScopeSessionListeners(super.getSecurityManager());
        } catch (Throwable e) {
            log.warn("Unable to add scope session listeners", e);
        }
    }

    @Override
    public void setSecurityManager(WebSecurityManager sm) {
        super.setSecurityManager(new WrappedSecurityManager(sm));
    }

    @Override
    @SneakyThrows
    protected void executeChain(ServletRequest request, ServletResponse response,
            FilterChain origChain) throws IOException, ServletException {
        if (isShiroEEDisabled(getServletContext())) {
            origChain.doFilter(request, response);
        } else if (Boolean.TRUE.equals(request.getAttribute(FORM_IS_RESUBMITTED)) && isPostRequest(request)) {
            setCharacterEncodingIfNeeded(request);
            request.removeAttribute(FORM_IS_RESUBMITTED);
            String postData = getPostData(request);
            log.debug("Resubmitting Post Data: {}", postData);
            var httpRequest = WebUtils.toHttp(request);
            boolean rememberedAjaxResubmit = "partial/ajax".equals(httpRequest.getHeader("Faces-Request"));
            Optional.ofNullable(resubmitSavedForm(postData,
                    Servlets.getRequestURLWithQueryString(httpRequest),
                    WebUtils.toHttp(request), WebUtils.toHttp(response),
                    request.getServletContext(), rememberedAjaxResubmit))
                    .ifPresent(url -> sendRedirect(response, url));
        } else {
            setCharacterEncodingIfNeeded(request);
            super.executeChain(request, response, origChain);
        }
    }

    @SneakyThrows(IOException.class)
    private static void sendRedirect(ServletResponse response, String url) {
        WebUtils.toHttp(response).sendRedirect(url);
    }

    @SuppressWarnings("LineLength")
    private static void setCharacterEncodingIfNeeded(ServletRequest request)
            throws UnsupportedEncodingException {
        // See https://stackoverflow.com/questions/7643484/how-to-get-rid-of-warning-pwc4011-unable-to-set-request-character-encoding-to
        if (isCharEncodingEnabled(request.getServletContext())) {
            Charset encoding = getCharacterEncoding(request.getServletContext());
            if (!encoding.name().equals(request.getCharacterEncoding())) {
                request.setCharacterEncoding(encoding.name());
            }
        }
    }
}
