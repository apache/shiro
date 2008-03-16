/*
 * Copyright 2005-2008 Les Hazlewood, Jeremy Haile
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.web.servlet;

import static org.jsecurity.util.StringUtils.*;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.SecurityWebSupport;
import org.jsecurity.web.interceptor.DefaultInterceptorBuilder;
import org.jsecurity.web.interceptor.InterceptorBuilder;
import org.jsecurity.web.interceptor.PathConfigWebInterceptor;
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

    private static final String[] CONFIG_SECTIONS = {"[global]", "[interceptors]", "[urls]"};

    protected String config = null;
    protected String global = null;
    protected String interceptors = null;
    protected String urls = null;
    protected String unauthorizedPage;

    protected Map<String, Object> filtersAndInterceptors;

    protected InterceptorBuilder interceptorBuilder = new DefaultInterceptorBuilder();

    private List<Filter> filters;

    public Map<String, Object> getFiltersAndInterceptors() {
        return filtersAndInterceptors;
    }

    public void setFiltersAndInterceptors(Map<String, Object> filtersAndInterceptors) {
        this.filtersAndInterceptors = filtersAndInterceptors;
    }

    public String getConfig() {
        return config;
    }

    public void setConfig(String config) {
        this.config = config;
    }

    public String getGlobal() {
        return global;
    }

    public void setGlobal(String global) {
        this.global = global;
    }

    public String getInterceptors() {
        return interceptors;
    }

    public void setInterceptors(String interceptors) {
        this.interceptors = interceptors;
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

    protected void afterSecurityManagerSet() throws Exception {
        applyInitParams();
        applyConfig();
        ensureWebInterceptors();
        applyUrlMappings();
        applyWebInterceptorFilters();
    }

    protected void applyConfig() throws Exception {

        String config = getConfig();
        //The following 3 values will be non-null if they have been overidden.
        //If they are overridden, we don't set them in the scanning below so that we
        //retain user-configured values.
        String global = getGlobal();
        String interceptors = getInterceptors();
        String urls = getUrls();

        if (config != null) {

            boolean inGlobal = false;
            boolean inInterceptors = false;

            StringBuffer section = new StringBuffer();
            Scanner scanner = new Scanner(config);
            while (scanner.hasNextLine()) {

                String line = clean(scanner.nextLine());
                //ignore comments:
                if ( line != null && line.startsWith( "#" ) ) {
                    line = null;
                }
                
                if (line != null) {
                    if (CONFIG_SECTIONS[0].equals(line.toLowerCase())) {
                        inGlobal = true;
                        if ( log.isDebugEnabled() ) {
                            log.debug( "Parsing " + CONFIG_SECTIONS[0] );
                        }
                    } else if (CONFIG_SECTIONS[1].equals(line.toLowerCase())) {
                        if (inGlobal) {
                            if (global == null && section.length() > 0) { //only set if not set previously by the user
                                global = section.toString();
                                setGlobal(global);
                            }
                        }
                        section = new StringBuffer();
                        inGlobal = false;
                        inInterceptors = true;
                        if ( log.isDebugEnabled() ) {
                            log.debug( "Parsing " + CONFIG_SECTIONS[1] );
                        }
                    } else if (CONFIG_SECTIONS[2].equals(line.toLowerCase())) {
                        if (inInterceptors) {
                            if (interceptors == null && section.length() > 0) { //only set if not set previously by the user
                                interceptors = section.toString();
                                setInterceptors(interceptors);
                            }
                        }
                        section = new StringBuffer();
                        inInterceptors = false;
                        inGlobal = false;
                        if ( log.isDebugEnabled() ) {
                            log.debug( "Parsing " + CONFIG_SECTIONS[2] );
                        }
                    } else {
                        section.append(line).append("\n");
                    }
                }
            }

            if (urls == null && section.length() > 0) {
                urls = section.toString();
                setUrls(urls);
            }
        }
    }

    protected void applyInitParams() {
        FilterConfig config = getFilterConfig();

        //only apply init params for the properties that are null - this allows subclasses to set the values
        //before the init params are read, which essentially allows overrides.
        if (getConfig() == null) {
            setConfig( clean(config.getInitParameter("config") ) );
        }
    }

    protected void ensureWebInterceptors() {
        Map<String, Object> interceptors = this.interceptorBuilder.buildInterceptors(getInterceptors());

        if (this.filtersAndInterceptors != null && !this.filtersAndInterceptors.isEmpty()) {
            interceptors.putAll(this.filtersAndInterceptors);
        }

        if (!interceptors.isEmpty()) {
            setFiltersAndInterceptors(interceptors);
        }
    }

    protected void applyWebInterceptorFilters() throws ServletException {

        Map<String, Object> interceptors = getFiltersAndInterceptors();

        if (log.isDebugEnabled()) {
            log.debug("Interceptors configured: " + interceptors.size());
        }

        if (interceptors != null && !interceptors.isEmpty()) {

            List<Filter> filters = new ArrayList<Filter>(interceptors.size());

            for (String key : interceptors.keySet()) {

                Object value = interceptors.get(key);

                Filter filter = null;

                if ( value instanceof Filter ) {
                    filter = (Filter)value;
                } else if ( value instanceof WebInterceptor ) {
                    WebInterceptor interceptor = (WebInterceptor) value;
                    WebInterceptorFilter wiFilter = new WebInterceptorFilter();
                    wiFilter.setWebInterceptor(interceptor);
                    filter = wiFilter;
                } else if ( value != null ) {
                    String msg = "filtersAndInterceptors collection contains an object of type [" +
                            value.getClass().getName() + "].  This instance does not implement " +
                            Filter.class.getName() + " or the " + WebInterceptor.class.getName() + " interfaces.  " +
                            "Only filters and interceptors should be configured.";
                    throw new ServletException(msg);

                }

                if (filter != null) {
                    filter.init(getFilterConfig());
                    filters.add(filter);
                }
            }

            this.filters = filters;
        }

        if (log.isDebugEnabled()) {
            log.debug("Filters configured and/or wrapped: " + (filters != null ? filters.size() : 0));
        }
    }

    protected void applyUrlMappings() throws ParseException {

        if (this.urls == null || this.filtersAndInterceptors == null || this.filtersAndInterceptors.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("No urls or filters/interceptors to process.");
            }
            return;
        }

        if (log.isTraceEnabled()) {
            log.trace("Before url scanning.");
        }

        Scanner scanner = new Scanner(this.urls);
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine();
            String[] pathValue = splitKeyValue(line);
            String path = pathValue[0];
            String value = pathValue[1];

            if (log.isDebugEnabled()) {
                log.debug("Processing path [" + path + "] with value [" + value + "]");
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
                if (interceptor instanceof PathConfigWebInterceptor) {
                    if (log.isDebugEnabled()) {
                        log.debug("Applying path [" + path + "] to interceptor [" + name + "] " +
                                "with config [" + config + "]");
                    }
                    ((PathConfigWebInterceptor) interceptor).processPathConfig(path, config);
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
        if (this.filters != null && !this.filters.isEmpty()) {
            for (Filter filter : filters) {
                try {
                    filter.destroy();
                } catch (Exception e) {
                    if (log.isWarnEnabled()) {
                        log.warn("Unable to cleanly destroy filter [" + filter + "].  Ignoring (shutting down)...", e);
                    }
                }
            }
        }

        super.destroy();
    }
}
