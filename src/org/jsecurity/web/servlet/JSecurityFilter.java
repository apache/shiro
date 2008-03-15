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

import static org.jsecurity.util.StringUtils.*;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.SecurityWebSupport;
import org.jsecurity.web.authz.DefaultUrlAuthorizationHandler;
import org.jsecurity.web.authz.UrlAuthorizationHandler;
import org.jsecurity.web.interceptor.DefaultInterceptorBuilder;
import org.jsecurity.web.interceptor.InterceptorBuilder;
import org.jsecurity.web.interceptor.MatchingWebInterceptor;
import org.jsecurity.web.interceptor.WebInterceptor;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

/**
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.1
 */
public class JSecurityFilter extends SecurityManagerFilter {

    protected Map<String, Object> filtersAndInterceptors;
    protected String interceptors = null;
    protected String urls = null;
    protected String unauthorizedPage;

    protected InterceptorBuilder interceptorBuilder = new DefaultInterceptorBuilder();

    protected UrlAuthorizationHandler urlAuthorizationHandler;

    private List<Filter> filters;

    public Map<String, Object> getFiltersAndInterceptors() {
        return filtersAndInterceptors;
    }

    public void setFiltersAndInterceptors(Map<String, Object> filtersAndInterceptors) {
        this.filtersAndInterceptors = filtersAndInterceptors;
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

    protected void afterSecurityManagerSet() throws Exception {
        applyInitParams();
        ensureWebInterceptors();
        applyUrlMappings();
        applyWebInterceptorFilters();
    }

    protected void applyInitParams() {
        FilterConfig config = getFilterConfig();
        this.interceptors = clean(config.getInitParameter("interceptors"));
        this.urls = clean(config.getInitParameter("urls"));
        this.unauthorizedPage = clean(config.getInitParameter("unauthorizedPage"));
    }

    protected void ensureWebInterceptors() {
        Map<String, Object> interceptors = this.interceptorBuilder.buildInterceptors(this.interceptors);

        if (this.filtersAndInterceptors != null && !this.filtersAndInterceptors.isEmpty()) {
            interceptors.putAll(this.filtersAndInterceptors);
        }

        if (!interceptors.isEmpty()) {
            setFiltersAndInterceptors(interceptors);
        }
    }

    protected void applyWebInterceptorFilters() throws ServletException {

        Map<String, Object> interceptors = getFiltersAndInterceptors();

        if ( log.isDebugEnabled() ) {
            log.debug( "Interceptors configured: " + interceptors.size() );
        }

        if (interceptors != null && !interceptors.isEmpty()) {

            List<Filter> filters = new ArrayList<Filter>(interceptors.size());

            for( String key : interceptors.keySet() ) {

                Object value = interceptors.get(key);

                Filter filter = null;

                if (!(value instanceof Filter) && value instanceof WebInterceptor) {
                    WebInterceptor interceptor = (WebInterceptor) value;
                    WebInterceptorFilter wiFilter = new WebInterceptorFilter();
                    wiFilter.setWebInterceptor(interceptor);
                    filter = wiFilter;
                } else if ( value instanceof Filter ) {
                    filter = (Filter)value;
                }
                if ( filter != null ) {
                    filter.init(getFilterConfig());
                    filters.add(filter);
                }
            }

            this.filters = filters;
        }

        if ( log.isDebugEnabled() ) {
            log.debug( "Filters configured and/or wrapped: " + (filters != null ? filters.size() : 0) );
        }
    }

    protected void applyUrlMappings() throws ParseException {

        if (this.urls == null || this.filtersAndInterceptors == null || this.filtersAndInterceptors.isEmpty()) {
            if ( log.isDebugEnabled() ) {
                log.debug("No urls or filters/interceptors to process." );
            }
            return;
        }

        if ( log.isTraceEnabled() ) {
            log.trace("Before url scanning." );
        }

        Scanner scanner = new Scanner(this.urls);
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine();
            String[] pathValue = splitKeyValue(line);
            String path = pathValue[0];
            String value = pathValue[1];

            if ( log.isDebugEnabled() ) {
                log.debug( "Processing path [" + path + "] with value [" + value + "]" );
            }


            //parse the value by tokenizing it to get the resulting interceptor-specific config entries
            //
            //e.g. for a value of
            //
            //     "authc, roles[admin,user], perms[file:edit]"
            //
            // the resulting token array would equal
            //
            //     { "authc", "roles[admin,user]", "perms[file:edit]" }
            //
            String[] interceptorTokens = split(value, ',', '[', ']', true, true);

            //each token is specific to each web interceptor.
            //strip the name and extract any interceptor-specific config between brackets [ ]
            for (String token : interceptorTokens) {
                String[] nameAndConfig = token.split("\\[", 2);
                String name = nameAndConfig[0];
                String config = null;

                if (nameAndConfig.length == 2) {
                    config = nameAndConfig[1];
                    //if there was an open bracket, there was a close bracket, so strip it too:
                    config = config.substring(0, config.length() - 1);
                }

                //now we have the interceptor name, path and (possibly null) path-specific config.  Let's apply them:
                Object interceptor = this.filtersAndInterceptors.get(name);
                if (interceptor instanceof MatchingWebInterceptor) {
                    if (log.isDebugEnabled()) {
                        log.debug("Applying path [" + path + "] to interceptor [" + name + "] " +
                                "with config [" + config + "]");
                    }
                    ((MatchingWebInterceptor) interceptor).processPathConfig(path, config);
                }
            }
        }
    }

    protected void doFilterInternal(ServletRequest servletRequest, ServletResponse servletResponse,
                                    FilterChain origChain) throws ServletException, IOException {
        FilterChain chain = origChain;
        if (this.filters != null && !this.filters.isEmpty()) {
            if (log.isTraceEnabled()) {
                log.trace("Filters and/or WebInterceptors configured - wrapping FilterChain.");
            }
            chain = new FilterChainWrapper(chain, this.filters);
        } else {
            if (log.isTraceEnabled()) {
                log.trace("No Filters or WebInterceptors configured - FilterChain will not be wrapped.");
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

    public void destroy() {
        if ( this.filters != null && !this.filters.isEmpty() ) {
            for( Filter filter : filters ) {
                try {
                    filter.destroy();
                } catch (Exception e) {
                    if ( log.isWarnEnabled() ) {
                        log.warn("Unable to cleanly destroy filter [" + filter + "].  Ignoring (shutting down)...", e );
                    }
                }
            }
        }
        
        super.destroy();
    }
}
