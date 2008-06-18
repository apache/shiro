/*
 * Copyright 2008 Les Hazlewood
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
package org.jsecurity.web.config;

import org.jsecurity.config.ConfigurationException;
import org.jsecurity.config.IniConfiguration;
import org.jsecurity.config.ReflectionBuilder;
import org.jsecurity.mgt.RealmSecurityManager;
import org.jsecurity.util.AntPathMatcher;
import static org.jsecurity.util.StringUtils.split;
import org.jsecurity.web.DefaultWebSecurityManager;
import static org.jsecurity.web.WebUtils.getPathWithinApplication;
import static org.jsecurity.web.WebUtils.toHttp;
import org.jsecurity.web.interceptor.PathConfigWebInterceptor;
import org.jsecurity.web.interceptor.authc.BasicHttpAuthenticationWebInterceptor;
import org.jsecurity.web.interceptor.authc.FormAuthenticationWebInterceptor;
import org.jsecurity.web.interceptor.authz.PermissionsAuthorizationWebInterceptor;
import org.jsecurity.web.interceptor.authz.RolesAuthorizationWebInterceptor;
import org.jsecurity.web.servlet.FilterChainWrapper;

import javax.servlet.*;
import java.util.*;

/**
 * TODO - Class JavaDoc
 *
 * @author Les Hazlewood
 * @since Jun 1, 2008 11:02:44 PM
 */
public class WebIniConfiguration extends IniConfiguration implements WebConfiguration {

    public static final String INTERCEPTORS = "interceptors";
    public static final String URLS = "urls";

    protected FilterConfig filterConfig;

    protected Map<String, List<Filter>> chains;

    protected AntPathMatcher pathMatcher = new AntPathMatcher();

    public WebIniConfiguration() {
        chains = new LinkedHashMap<String, List<Filter>>();
    }

    public FilterConfig getFilterConfig() {
        return filterConfig;
    }

    public void setFilterConfig(FilterConfig filterConfig) {
        this.filterConfig = filterConfig;
    }

    public FilterChain getChain(ServletRequest request, ServletResponse response, FilterChain originalChain) {
        if (this.chains == null || this.chains.isEmpty()) {
            return null;
        }

        String requestURI = getPathWithinApplication(toHttp(request));

        for (String path : this.chains.keySet()) {

            // If the path does match, then pass on to the subclass implementation for specific checks:
            if (pathMatcher.match(path, requestURI)) {
                if (log.isTraceEnabled()) {
                    log.trace("Matched path [" + path + "] for requestURI [" + requestURI + "].  " +
                            "Utilizing corresponding filter chain...");
                }
                List<Filter> pathFilters = this.chains.get(path);
                if (pathFilters != null && !pathFilters.isEmpty()) {
                    return new FilterChainWrapper(originalChain, pathFilters);
                }
            }
        }

        return null;
    }

    protected RealmSecurityManager newSecurityManagerInstance() {
        return new DefaultWebSecurityManager();
    }

    /**
     * 1.  First builds the interceptor and/or filter instances.
     * 2.  Applys url mappings to these interceptors and/or filters
     * 3.  Creates a collection of Filter objects that will be used by the JSecurityFilter.
     *
     * @param sections
     */
    protected void afterSecurityManagerSet(Map<String, Map<String, String>> sections) {
        //interceptors section:
        Map<String, String> section = sections.get(INTERCEPTORS);
        Map<String, Filter> filters = getFilters(section);

        //urls section:
        section = sections.get(URLS);
        this.chains = prepareChains(section, filters);

        initFilters(this.chains);
    }

    protected void initFilters(Map<String, List<Filter>> chains) {
        if (chains == null || chains.isEmpty()) {
            return;
        }
        //add 'em to a set so we only initialize once:
        Set<Filter> filters = new LinkedHashSet<Filter>();
        for (List<Filter> pathFilters : chains.values()) {
            filters.addAll(pathFilters);
        }
        for (Filter filter : filters) {
            initFilter(filter);
        }
    }

    protected void initFilter(Filter f) {
        try {
            f.init(getFilterConfig());
        } catch (ServletException e) {
            throw new ConfigurationException(e);
        }
    }

    @SuppressWarnings({"unchecked"})
    protected Map<String, Filter> getFilters(Map<String, String> interceptorsSection) {

        Map<String, Filter> filters = buildDefaultInterceptors();

        if (interceptorsSection != null && !interceptorsSection.isEmpty()) {
            ReflectionBuilder builder = new ReflectionBuilder(filters);
            Map built = builder.buildObjects(interceptorsSection);
            assertFilters(built);
            filters = (Map<String, Filter>) built;
        }

        return filters;
    }

    protected void assertFilters(Map<String, ?> map) {
        if (map == null || map.isEmpty()) {
            return;
        }
        for (Map.Entry<String, ?> entry : map.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            assertFilter(key, value);
        }
    }

    protected void assertFilter(String name, Object o) throws ConfigurationException {
        if (!(o instanceof Filter)) {
            String msg = "[interceptors] section specified a filter named '" + name + "', which does not " +
                    "implement the " + Filter.class.getName() + " interface.  Only Filter implementations may be " +
                    "can be interceptors.";
            throw new ConfigurationException(msg);
        }
    }

    protected Map<String, Filter> buildDefaultInterceptors() {
        Map<String, Filter> interceptors = new LinkedHashMap<String, Filter>();
        interceptors.put("authc", new FormAuthenticationWebInterceptor());
        interceptors.put("authcBasic", new BasicHttpAuthenticationWebInterceptor());
        interceptors.put("roles", new RolesAuthorizationWebInterceptor());
        interceptors.put("perms", new PermissionsAuthorizationWebInterceptor());
        return interceptors;
    }

    public Map<String, List<Filter>> prepareChains(Map<String, String> urls, Map<String, Filter> filters) {
        if (urls == null || urls.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("No urls to process.");
            }
            return null;
        }
        if (filters == null || filters.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("No filters to process.");
            }
            return null;
        }

        if (log.isTraceEnabled()) {
            log.trace("Before url processing.");
        }

        Map<String, List<Filter>> pathChains = new LinkedHashMap<String, List<Filter>>(urls.size());

        for (Map.Entry<String, String> entry : urls.entrySet()) {
            String path = entry.getKey();
            String value = entry.getValue();

            if (log.isDebugEnabled()) {
                log.debug("Processing path [" + path + "] with value [" + value + "]");
            }

            List<Filter> pathFilters = new ArrayList<Filter>();

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
                Filter filter = filters.get(name);
                if (filter == null) {
                    String msg = "Path [" + path + "] specified an interceptor named '" + name + "', but that " +
                            "interceptor has not been specified in the [interceptors] section.";
                    throw new ConfigurationException(msg);
                }
                if (filter instanceof PathConfigWebInterceptor) {
                    if (log.isDebugEnabled()) {
                        log.debug("Applying path [" + path + "] to filter [" + name + "] " +
                                "with config [" + config + "]");
                    }
                    ((PathConfigWebInterceptor) filter).processPathConfig(path, config);
                }

                pathFilters.add(filter);
            }

            if (!pathFilters.isEmpty()) {
                pathChains.put(path, pathFilters);
            }
        }

        if (pathChains.isEmpty()) {
            return null;
        }

        return pathChains;
    }
}
