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
package org.apache.shiro.web.filter;

import org.apache.shiro.ShiroException;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.util.Nameable;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.filter.authc.AnonymousFilter;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.filter.authc.UserFilter;
import org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter;
import org.apache.shiro.web.filter.authz.PortFilter;
import org.apache.shiro.web.filter.authz.RolesAuthorizationFilter;
import org.apache.shiro.web.filter.authz.SslFilter;
import org.apache.shiro.web.servlet.ProxiedFilterChain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import java.util.*;

/**
 * @since 1.0
 */
public class DefaultFilterChainManager implements FilterChainManager, Initializable {

    private static transient final Logger log = LoggerFactory.getLogger(DefaultFilterChainManager.class);

    private FilterConfig filterConfig;

    private Map<String, Filter> filters; //pool of filters available for creating filters

    private Map<String, NamedFilterList> filterChains; //name to filter chain mapping

    public DefaultFilterChainManager() {
        this.filters = new LinkedHashMap<String, Filter>();
        this.filterChains = new LinkedHashMap<String, NamedFilterList>();
    }

    public DefaultFilterChainManager(FilterConfig filterConfig) {
        this();
        init(filterConfig);
    }

    /**
     * Returns the {@code FilterConfig} provided by the Servlet container at webapp startup.
     *
     * @return the {@code FilterConfig} provided by the Servlet container at webapp startup.
     */
    public FilterConfig getFilterConfig() {
        return filterConfig;
    }

    /**
     * Sets the {@code FilterConfig} provided by the Servlet container at webapp startup.
     *
     * @param filterConfig the {@code FilterConfig} provided by the Servlet container at webapp startup.
     */
    public void setFilterConfig(FilterConfig filterConfig) {
        this.filterConfig = filterConfig;
    }

    public Map<String, Filter> getFilters() {
        return filters;
    }

    public void setFilters(Map<String, Filter> filters) {
        this.filters = filters;
    }

    public Map<String, NamedFilterList> getFilterChains() {
        return filterChains;
    }

    public void setFilterChains(Map<String, NamedFilterList> filterChains) {
        this.filterChains = filterChains;
    }

    public void init() throws ShiroException {
        if (this.filterConfig == null) {
            throw new IllegalStateException("filterConfig attribute must be set.");
        }
        addDefaultFilters();
    }

    public void init(FilterConfig filterConfig) throws ShiroException {
        setFilterConfig(filterConfig);
        init();
    }

    public Filter getFilter(String name) {
        return this.filters.get(name);
    }

    public void addFilter(String name, Filter filter) {
        addFilter(name, filter, true);
    }

    public void addFilter(String name, Filter filter, boolean init) {
        addFilter(name, filter, init, true);
    }

    protected void addFilter(String name, Filter filter, boolean init, boolean overwrite) {
        Filter existing = getFilter(name);
        if (existing == null || overwrite) {
            if (init) {
                initFilter(filter);
            }
            this.filters.put(name, filter);
        }
    }

    public void addToChain(String chainName, String filterName) {
        addToChain(chainName, filterName, null);
    }

    protected void applyChainConfig(String chainName, Filter filter, String chainSpecificFilterConfig) {
        if (filter instanceof PathConfigProcessor) {
            ((PathConfigProcessor) filter).processPathConfig(chainName, chainSpecificFilterConfig);
        } else {
            String msg = "chainSpecificFilterConfig was specified as a method argument, but the underlying " +
                    "Filter instance is not an 'instanceof' " +
                    PathConfigProcessor.class.getName() + ".  This is required if the filter is to accept " +
                    "chain-specific configuration.";
            throw new IllegalArgumentException(msg);
        }
    }

    protected NamedFilterList ensureChain(String chainName) {
        NamedFilterList chain = getChain(chainName);
        if (chain == null) {
            chain = new SimpleNamedFilterList(chainName);
            this.filterChains.put(chainName, chain);
        }
        return chain;
    }

    public void addToChain(String chainName, String filterName, String chainSpecificFilterConfig) {
        Filter filter = getFilter(filterName);
        if (filter == null) {
            throw new IllegalArgumentException("There is no filter with name '" + filterName +
                    "' to apply to chain [" + chainName + "]");
        }
        if (StringUtils.hasText(chainSpecificFilterConfig)) {
            applyChainConfig(chainName, filter, chainSpecificFilterConfig);
        }

        NamedFilterList chain = ensureChain(chainName);
        chain.add(filter);
    }

    public NamedFilterList getChain(String chainName) {
        return this.filterChains.get(chainName);
    }

    public boolean hasChains() {
        return !CollectionUtils.isEmpty(this.filterChains);
    }

    public Set<String> getChainNames() {
        //noinspection unchecked
        return this.filterChains != null ? this.filterChains.keySet() : Collections.EMPTY_SET;
    }

    public FilterChain proxy(FilterChain original, String chainName) {
        NamedFilterList configured = getChain(chainName);
        if (configured == null) {
            String msg = "There is no configured chain under the name/key [" + chainName + "].";
            throw new IllegalArgumentException(msg);
        }
        return configured.proxy(original);
    }

    /**
     * Returns the {@code FilterChain} to use for the specified application path, or {@code null} if there
     * was not a configured chain for the specified path.
     * <p/>
     * The default implementation simply calls <code>this.chains.get(chainUrl)</code> to acquire the configured
     * {@code List&lt;Filter&gt;} filter chain.  If that configured chain is non-null and not empty, it is
     * returned, otherwise {@code null} is returned to indicate that the {@code originalChain} should be
     * used instead.
     *
     * @param chainUrl      the configured filter chain url
     * @param originalChain the original FilterChain given by the Servlet container.
     * @return the {@code FilterChain} to use for the specified application path, or {@code null} if the
     *         original {@code FilterChain} should be used.
     */
    public FilterChain getChain(String chainUrl, FilterChain originalChain) {
        Map<String, NamedFilterList> filterChains = getFilterChains();
        List<Filter> pathFilters = filterChains != null ? filterChains.get(chainUrl) : null;
        if (!CollectionUtils.isEmpty(pathFilters)) {
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
     * <code>new {@link org.apache.shiro.web.servlet.ProxiedFilterChain FilterChainWrapper(filters, originalChain)}</code>,
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
     * Initializes the filter by calling <code>filter.init( {@link #getFilterConfig() getFilterConfig()} );</code>.
     *
     * @param filter the filter to initialize with the <code>FilterConfig</code>.
     */
    protected void initFilter(Filter filter) {
        FilterConfig filterConfig = getFilterConfig();
        if (filterConfig == null) {
            throw new IllegalStateException("FilterConfig attribute has not been set.  This must occur before filter " +
                    "initialization can occur.");
        }
        try {
            filter.init(filterConfig);
        } catch (ServletException e) {
            throw new ConfigurationException(e);
        }
    }

    protected void createFilters() {
        addDefaultFilters();
    }

    protected void addFilterIfNecessary(String name, Filter filter) {
        if (getFilter(name) == null) {
            //has not been added yet, so add it now:
            if (filter instanceof Nameable) {
                ((Nameable) filter).setName(name);
            }
            addFilter(name, filter);
        }
    }

    protected void addDefaultFilters() {
        addFilter("anon", new AnonymousFilter(), true, false);
        addFilter("user", new UserFilter(), true, false);
        addFilter("authc", new FormAuthenticationFilter(), true, false);
        addFilter("authcBasic", new BasicHttpAuthenticationFilter(), true, false);
        addFilter("roles", new RolesAuthorizationFilter(), true, false);
        addFilter("perms", new PermissionsAuthorizationFilter(), true, false);
        addFilter("port", new PortFilter(), true, false);
        addFilter("ssl", new SslFilter(), true, false);
    }
}
