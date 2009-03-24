/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.ki.web.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.ki.config.ConfigurationException;
import org.apache.ki.config.IniConfiguration;
import org.apache.ki.config.ReflectionBuilder;
import org.apache.ki.mgt.RealmSecurityManager;
import org.apache.ki.util.AntPathMatcher;
import org.apache.ki.util.PatternMatcher;
import static org.apache.ki.util.StringUtils.split;
import org.apache.ki.web.DefaultWebSecurityManager;
import org.apache.ki.web.WebUtils;
import org.apache.ki.web.filter.PathConfigProcessor;
import org.apache.ki.web.filter.authc.AnonymousFilter;
import org.apache.ki.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.ki.web.filter.authc.FormAuthenticationFilter;
import org.apache.ki.web.filter.authc.UserFilter;
import org.apache.ki.web.filter.authz.PermissionsAuthorizationFilter;
import org.apache.ki.web.filter.authz.RolesAuthorizationFilter;
import org.apache.ki.web.servlet.AdviceFilter;
import org.apache.ki.web.servlet.ProxiedFilterChain;


/**
 * A <code>WebConfiguration</code> that supports configuration via the
 * <a href="http://en.wikipedia.org/wiki/INI_file">.ini format</a>.
 *
 * @author Les Hazlewood
 * @since Jun 1, 2008 11:02:44 PM
 */
public class IniWebConfiguration extends IniConfiguration implements WebConfiguration {

    //TODO - complete JavaDoc

    private static final transient Log log = LogFactory.getLog(IniWebConfiguration.class);

    public static final String FILTERS = "filters";
    public static final String URLS = "urls";

    protected FilterConfig filterConfig;

    protected Map<String, List<Filter>> chains;

    protected PatternMatcher pathMatcher = new AntPathMatcher();

    public IniWebConfiguration() {
        chains = new LinkedHashMap<String, List<Filter>>();
    }

    /**
     * Returns the <code>PatternMatcher</code> used when determining if an incoming request's path
     * matches a configured filter chain path in the <code>[urls]</code> section.  Unless overridden, the
     * default implementation is an {@link org.apache.ki.util.AntPathMatcher AntPathMatcher}.
     *
     * @return the <code>PatternMatcher</code> used when determining if an incoming request's path
     *         matches a configured filter chain path in the <code>[urls]</code> section.
     * @since 0.9.0
     */
    public PatternMatcher getPathMatcher() {
        return pathMatcher;
    }

    /**
     * Sets the <code>PatternMatcher</code> used when determining if an incoming request's path
     * matches a configured filter chain path in the <code>[urls]</code> section.  Unless overridden, the
     * default implementation is an {@link org.apache.ki.util.AntPathMatcher AntPathMatcher}.
     *
     * @param pathMatcher the <code>PatternMatcher</code> used when determining if an incoming request's path
     *                    matches a configured filter chain path in the <code>[urls]</code> section.
     * @since 0.9.0
     */
    public void setPathMatcher(PatternMatcher pathMatcher) {
        this.pathMatcher = pathMatcher;
    }

    /**
     * Returns the <code>FilterConfig</code> provided by the Servlet container at webapp startup.
     *
     * @return the <code>FilterConfig</code> provided by the Servlet container at webapp startup.
     */
    public FilterConfig getFilterConfig() {
        return filterConfig;
    }

    /**
     * Sets the <code>FilterConfig</code> provided by the Servlet container at webapp startup.
     *
     * @param filterConfig the <code>FilterConfig</code> provided by the Servlet container at webapp startup.
     */
    public void setFilterConfig(FilterConfig filterConfig) {
        this.filterConfig = filterConfig;
    }

    //TODO - JAVADOC
    public FilterChain getChain(ServletRequest request, ServletResponse response, FilterChain originalChain) {
        if (this.chains == null || this.chains.isEmpty()) {
            return null;
        }

        String requestURI = getPathWithinApplication(request);

        for (String path : this.chains.keySet()) {

            // If the path does match, then pass on to the subclass implementation for specific checks:
            if (pathMatches(path, requestURI)) {
                if (log.isTraceEnabled()) {
                    log.trace("Matched path [" + path + "] for requestURI [" + requestURI + "].  " +
                            "Utilizing corresponding filter chain...");
                }
                return getChain(path, originalChain);
            }
        }

        return null;
    }

    /**
     * Returns the <code>FilterChain</code> to use for the specified application path, or <code>null</code> if the
     * original <code>FilterChain</code> should be used.
     * <p/>
     * The default implementation simply calls <code>this.chains.get(chainUrl)</code> to acquire the configured
     * <code>List&lt;Filter&gt;</code> filter chain.  If that configured chain is non-null and not empty, it is
     * returned, otherwise <code>null</code> is returned to indicate that the <code>originalChain</code> should be
     * used instead.
     *
     * @param chainUrl      the configured filter chain url
     * @param originalChain the original FilterChain given by the Servlet container.
     * @return the <code>FilterChain</code> to use for the specified application path, or <code>null</code> if the
     *         original <code>FilterChain</code> should be used.
     */
    protected FilterChain getChain(String chainUrl, FilterChain originalChain) {
        List<Filter> pathFilters = this.chains.get(chainUrl);
        if (pathFilters != null && !pathFilters.isEmpty()) {
            return createChain(pathFilters, originalChain);
        }
        return null;
    }

    /**
     * Creates a new FilterChain based on the specified configured url filter chain and original chain.
     * <p/>
     * The input arguments are expected be be non-null and non-empty, since these conditions are accounted for in the
     * {@link #getChain(String, javax.servlet.FilterChain) getChain(chainUrl,originalChain)} implementation that
     * calls this method.
     * <p/>
     * The default implementation merely returns
     * <code>new {@link org.apache.ki.web.servlet.ProxiedFilterChain FilterChainWrapper(filters, originalChain)}</code>,
     * and can be overridden by subclasses for custom creation.
     *
     * @param filters       the configured filter chain for the incoming request application path
     * @param originalChain the original FilterChain given by the Servlet container.
     * @return a new FilterChain based on the specified configured url filter chain and original chain.
     */
    protected FilterChain createChain(List<Filter> filters, FilterChain originalChain) {
        return new ProxiedFilterChain(originalChain, filters);
    }

    /**
     * Returns <code>true</code> if an incoming request's path (the <code>path</code> argument)
     * matches a configured filter chain path in the <code>[urls]</code> section (the <code>pattern</code> argument),
     * <code>false</code> otherwise.
     * <p/>
     * Simply delegates to
     * <b><code>{@link #getPathMatcher() getPathMatcher()}.{@link org.apache.ki.util.PatternMatcher#matches(String, String) matches(pattern,path)}</code></b>,
     * but can be overridden by subclasses for custom matching behavior.
     *
     * @param pattern the pattern to match against
     * @param path    the value to match with the specified <code>pattern</code>
     * @return <code>true</code> if the request <code>path</code> matches the specified filter chain url <code>pattern</code>,
     *         <code>false</code> otherwise.
     */
    protected boolean pathMatches(String pattern, String path) {
        PatternMatcher pathMatcher = getPathMatcher();
        return pathMatcher.matches(pattern, path);
    }

    /**
     * Merely returns
     * <code>WebUtils.{@link org.apache.ki.web.WebUtils#getPathWithinApplication(javax.servlet.http.HttpServletRequest) getPathWithinApplication(request)}</code>
     * and can be overridden by subclasses for custom request-to-application-path resolution behavior.
     *
     * @param request the incoming <code>ServletRequest</code>
     * @return the request's path within the appliation.
     */
    protected String getPathWithinApplication(ServletRequest request) {
        return WebUtils.getPathWithinApplication(WebUtils.toHttp(request));
    }

    /**
     * Creates a new, uninitialized <code>SecurityManager</code> instance that will be used to build up
     * the Apache Ki environment for the web application.
     * <p/>
     * The default implementation simply returns
     * <code>new {@link org.apache.ki.web.DefaultWebSecurityManager DefaultWebSecurityManager()};</code>
     *
     * @return a new, uninitialized <code>SecurityManager</code> instance that will be used to build up
     *         the Apache Ki environment for the web application.
     */
    protected RealmSecurityManager newSecurityManagerInstance() {
        return new DefaultWebSecurityManager();
    }

    /**
     * This implementation:
     * <ol>
     * <li>First builds the filter instances by processing the [filters] section</li>
     * <li>Builds a collection filter chains according to the definitions in the [urls] section</li>
     * <li>Initializes the filter instances in the order in which they were defined</li>
     * </ol>
     *
     * @param sections the configured .ini sections where the key is the section name (without [] brackets)
     *                 and the value is the key/value pairs inside that section.
     */
    protected void afterSecurityManagerSet(Map<String, Map<String, String>> sections) {
        //filters section:
        Map<String, String> section = sections.get(FILTERS);
        Map<String, Filter> filters = getFilters(section);

        //urls section:
        section = sections.get(URLS);
        this.chains = createChains(section, filters);

        initFilters(this.chains);
    }

    protected void initFilters(Map<String, List<Filter>> chains) {
        if (chains == null || chains.isEmpty()) {
            return;
        }

        //add 'em to a set so we only initialize each one once:
        Set<Filter> filters = new LinkedHashSet<Filter>();
        for (List<Filter> pathFilters : chains.values()) {
            filters.addAll(pathFilters);
        }

        //now initialize each one:
        for (Filter filter : filters) {
            initFilter(filter);
        }
    }

    /**
     * Initializes the filter by calling <code>filter.init( {@link #getFilterConfig() getFilterConfig()} );</code>.
     *
     * @param filter the filter to initialize with the <code>FilterConfig</code>.
     */
    protected void initFilter(Filter filter) {
        try {
            filter.init(getFilterConfig());
        } catch (ServletException e) {
            throw new ConfigurationException(e);
        }
    }

    @SuppressWarnings({"unchecked"})
    protected Map<String, Filter> getFilters(Map<String, String> section) {

        Map<String, Filter> filters = createDefaultFilters();

        if (section != null && !section.isEmpty()) {
            ReflectionBuilder builder = new ReflectionBuilder(filters);
            Map built = builder.buildObjects(section);
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
            String msg = "[" + FILTERS + "] section specified a filter named '" + name + "', which does not " +
                    "implement the " + Filter.class.getName() + " interface.  Only Filter implementations may be " +
                    "defined.";
            throw new ConfigurationException(msg);
        }
    }

    protected Map<String, Filter> createDefaultFilters() {
        Map<String, Filter> filters = new LinkedHashMap<String, Filter>();

        String name = "anon";
        AdviceFilter filter = new AnonymousFilter();
        filter.setName(name);
        filters.put(name, filter);

        name = "user";
        filter = new UserFilter();
        filter.setName(name);
        filters.put(name, filter);

        name = "authc";
        filter = new FormAuthenticationFilter();
        filter.setName(name);
        filters.put(name, filter);

        name = "authcBasic";
        filter = new BasicHttpAuthenticationFilter();
        filter.setName(name);
        filters.put(name, filter);

        name = "roles";
        filter = new RolesAuthorizationFilter();
        filter.setName(name);
        filters.put(name, filter);

        name = "perms";
        filter = new PermissionsAuthorizationFilter();
        filter.setName(name);
        filters.put(name, filter);

        return filters;
    }

    public Map<String, List<Filter>> createChains(Map<String, String> urls, Map<String, Filter> filters) {
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

            //parse the value by tokenizing it to get the resulting filter-specific config entries
            //
            //e.g. for a value of
            //
            //     "authc, roles[admin,user], perms[file:edit]"
            //
            // the resulting token array would equal
            //
            //     { "authc", "roles[admin,user]", "perms[file:edit]" }
            //
            String[] filterTokens = split(value, ',', '[', ']', true, true);

            //each token is specific to each filter.
            //strip the name and extract any filter-specific config between brackets [ ]
            for (String token : filterTokens) {
                String[] nameAndConfig = token.split("\\[", 2);
                String name = nameAndConfig[0];
                String config = null;

                if (nameAndConfig.length == 2) {
                    config = nameAndConfig[1];
                    //if there was an open bracket, there was a close bracket, so strip it too:
                    config = config.substring(0, config.length() - 1);
                }

                //now we have the filter name, path and (possibly null) path-specific config.  Let's apply them:
                Filter filter = filters.get(name);
                if (filter == null) {
                    String msg = "Path [" + path + "] specified a filter named '" + name + "', but that " +
                            "filter has not been specified in the [" + FILTERS + "] section.";
                    throw new ConfigurationException(msg);
                }
                if (filter instanceof PathConfigProcessor) {
                    if (log.isDebugEnabled()) {
                        log.debug("Applying path [" + path + "] to filter [" + name + "] " +
                                "with config [" + config + "]");
                    }
                    ((PathConfigProcessor) filter).processPathConfig(path, config);
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
