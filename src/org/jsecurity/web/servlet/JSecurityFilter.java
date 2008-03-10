/*
 * Copyright (C) 2005-2008 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.web.servlet;

import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.SecurityWebSupport;
import org.jsecurity.web.WebInterceptor;
import org.jsecurity.web.authz.*;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.1
 */
public class JSecurityFilter extends SecurityManagerFilter {

    protected List webInterceptors;
    protected String interceptors = null;
    protected String urls = null;
    protected String unauthorizedPage;

    protected InterceptorBuilder interceptorBuilder = new DefaultInterceptorBuilder();

    protected UrlAuthorizationHandler urlAuthorizationHandler;

    private List<Filter> filters;

    public List getWebInterceptors() {
        return webInterceptors;
    }

    public void setWebInterceptors(List webInterceptors) {
        this.webInterceptors = webInterceptors;
    }

    public String getUrls() {
        return urls;
    }

    public void setUrls(String urls) {
        this.urls = urls;
    }

    public String getUnauthorizedPage() {
        return unauthorizedPage;
    }

    public void setUnauthorizedPage(String unauthorizedPage) {
        this.unauthorizedPage = unauthorizedPage;
    }

    public UrlAuthorizationHandler getUrlAuthorizationHandler() {
        if (urlAuthorizationHandler == null) {
            urlAuthorizationHandler = new DefaultUrlAuthorizationHandler();
        }
        return urlAuthorizationHandler;
    }

    public void setUrlAuthorizationHandler(UrlAuthorizationHandler urlAuthorizationHandler) {
        this.urlAuthorizationHandler = urlAuthorizationHandler;
    }

    protected void applyInitParams() {
        FilterConfig config = getFilterConfig();

        this.interceptors = config.getInitParameter("interceptors");
        if ( this.interceptors != null ) {
            this.interceptors = this.interceptors.trim();
            if ( this.interceptors.equals("")) {
                this.interceptors = null;
            }
        }

        this.urls = config.getInitParameter("urls");
        this.unauthorizedPage = config.getInitParameter("unauthorizedPage");
    }

    protected void ensureWebInterceptors() {
        List interceptors = new ArrayList();

        if ( this.interceptors != null ) {
            interceptors = this.interceptorBuilder.buildInterceptors(this.interceptors);
        }

        List<WebInterceptor> configured = getWebInterceptors();

        String urls = getUrls();
        if (urls != null) {
            WebInterceptor uawi = new UrlAuthorizationWebInterceptor(getSecurityManager(), urls);
            interceptors.add(uawi);
        }

        if (configured != null && !configured.isEmpty()) {
            interceptors.addAll(configured);
        }

        if (!interceptors.isEmpty()) {
            setWebInterceptors(interceptors);
        }
    }

    protected void applyWebInterceptorFilters() {
        List<WebInterceptor> interceptors = getWebInterceptors();
        if (interceptors != null && !interceptors.isEmpty()) {
            List<Filter> filters = new ArrayList<Filter>(interceptors.size());
            for (WebInterceptor interceptor : interceptors) {
                WebInterceptorFilter filter = new WebInterceptorFilter();
                filter.setServletContext(getServletContext());
                filter.setWebInterceptor(interceptor);
                filter.afterSecurityManagerSet();
                filters.add(filter);
            }
            this.filters = filters;
        }
    }

    protected void afterSecurityManagerSet() throws Exception {
        applyInitParams();
        ensureWebInterceptors();
        applyWebInterceptorFilters();
    }

    protected void doFilterInternal(ServletRequest servletRequest, ServletResponse servletResponse,
                                    FilterChain origChain) throws ServletException, IOException {
        FilterChain chain = origChain;
        if (this.filters != null && !this.filters.isEmpty()) {
            if ( log.isTraceEnabled() ) {
                log.trace( "Filters and/or WebInterceptors configured - wrapping FilterChain." );
            }
            chain = new FilterChainWrapper(chain, this.filters);
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "No Filters or WebInterceptors configured - FilterChain will not be wrapped." );
            }
        }

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        ThreadContext.bind(SecurityWebSupport.getInetAddress(request));

        boolean httpSessions = isHttpSessions();
        request = new JSecurityHttpServletRequest(request, getServletContext(), httpSessions);
        if (!httpSessions) {
            //the JSecurityHttpServletResponse exists to support URL rewriting for session ids.  This is only needed if
            //using JSecurity sessions (i.e. not simple HttpSession based sessions):
            response = new JSecurityHttpServletResponse(response, getServletContext(), (JSecurityHttpServletRequest) request);
        }

        ThreadContext.bind(request);
        ThreadContext.bind(response);
        ThreadContext.bind(getSecurityManager().getSubject());

        try {
            chain.doFilter(request, response);
        } finally {
            ThreadContext.unbindServletRequest();
            ThreadContext.unbindServletResponse();
            ThreadContext.unbindInetAddress();
            ThreadContext.unbindSubject();
        }
    }
}
