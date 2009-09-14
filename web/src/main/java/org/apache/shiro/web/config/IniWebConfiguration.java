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
package org.apache.shiro.web.config;

import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.config.IniConfiguration;
import org.apache.shiro.config.ReflectionBuilder;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.web.DefaultWebSecurityManager;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;


/**
 * A <code>WebConfiguration</code> that supports configuration via the
 * <a href="http://en.wikipedia.org/wiki/INI_file">.ini format</a>.
 *
 * @author Les Hazlewood
 * @since Jun 1, 2008 11:02:44 PM
 */
public class IniWebConfiguration extends IniConfiguration implements WebConfiguration {

    //TODO - complete JavaDoc

    private static final transient Logger log = LoggerFactory.getLogger(IniWebConfiguration.class);

    public static final String FILTERS = "filters";
    public static final String URLS = "urls";

    protected FilterConfig filterConfig;

    private PathMatchingFilterChainResolver resolver;

    public IniWebConfiguration() {
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
    @SuppressWarnings({"UnusedDeclaration"})
    //called via Reflection - DO NOT REMOVE
    public void setFilterConfig(FilterConfig filterConfig) {
        this.filterConfig = filterConfig;
        this.resolver = new PathMatchingFilterChainResolver(filterConfig);
    }

    //TODO - JAVADOC
    public FilterChain getChain(ServletRequest request, ServletResponse response, FilterChain originalChain) {
        return resolver.getChain(request, response, originalChain);
    }

    /**
     * Creates a new, uninitialized <code>SecurityManager</code> instance that will be used to build up
     * the Shiro environment for the web application.
     * <p/>
     * The default implementation simply returns
     * <code>new {@link org.apache.shiro.web.DefaultWebSecurityManager DefaultWebSecurityManager()};</code>
     *
     * @return a new, uninitialized <code>SecurityManager</code> instance that will be used to build up
     *         the Shiro environment for the web application.
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
        createChains(section);

        initFilters(filters);
    }


    protected void initFilters(Map<String, Filter> filters) {
        if (CollectionUtils.isEmpty(filters)) {
            return;
        }

        //add 'em to a set so we only initialize each one once, just in case
        //for some reason a filter is mapped more than once:
        Collection<Filter> values = filters.values();
        Set<Filter> filtersToInit = new LinkedHashSet<Filter>(values);

        //now initialize each one:
        for (Filter filter : filtersToInit) {
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

        Map<String, Filter> filters = resolver.getFilterChainManager().getFilters();

        if (section != null && !section.isEmpty()) {
            ReflectionBuilder builder = new ReflectionBuilder(filters);
            Map<String, ?> built = builder.buildObjects(section);
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

    protected void createChains(Map<String, String> urls) {
        if (urls == null || urls.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("No urls to process.");
            }
            return;
        }

        if (log.isTraceEnabled()) {
            log.trace("Before url processing.");
        }

        for (Map.Entry<String, String> entry : urls.entrySet()) {
            String path = entry.getKey();
            String value = entry.getValue();
            resolver.getFilterChainManager().createChain(path, value);
        }
    }
}
