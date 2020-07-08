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
package org.apache.shiro.web.filter.mgt;

import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.lang.util.Nameable;
import org.apache.shiro.lang.util.StringUtils;
import org.apache.shiro.web.filter.PathConfigProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Default {@link FilterChainManager} implementation maintaining a map of {@link Filter Filter} instances
 * (key: filter name, value: Filter) as well as a map of {@link NamedFilterList NamedFilterList}s created from these
 * {@code Filter}s (key: filter chain name, value: NamedFilterList).  The {@code NamedFilterList} is essentially a
 * {@link FilterChain} that also has a name property by which it can be looked up.
 *
 * @see NamedFilterList
 * @since 1.0
 */
public class DefaultFilterChainManager implements FilterChainManager {

    private static transient final Logger log = LoggerFactory.getLogger(DefaultFilterChainManager.class);

    private FilterConfig filterConfig;

    private Map<String, Filter> filters; //pool of filters available for creating chains

    private List<String> globalFilterNames; // list of filters to prepend to every chain

    private Map<String, NamedFilterList> filterChains; //key: chain name, value: chain

    public DefaultFilterChainManager() {
        this.filters = new LinkedHashMap<String, Filter>();
        this.filterChains = new LinkedHashMap<String, NamedFilterList>();
        this.globalFilterNames = new ArrayList<>();
        addDefaultFilters(false);
    }

    public DefaultFilterChainManager(FilterConfig filterConfig) {
        this.filters = new LinkedHashMap<String, Filter>();
        this.filterChains = new LinkedHashMap<String, NamedFilterList>();
        this.globalFilterNames = new ArrayList<>();
        setFilterConfig(filterConfig);
        addDefaultFilters(true);
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

    @SuppressWarnings({"UnusedDeclaration"})
    public void setFilters(Map<String, Filter> filters) {
        this.filters = filters;
    }

    public Map<String, NamedFilterList> getFilterChains() {
        return filterChains;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setFilterChains(Map<String, NamedFilterList> filterChains) {
        this.filterChains = filterChains;
    }

    public Filter getFilter(String name) {
        return this.filters.get(name);
    }

    public void addFilter(String name, Filter filter) {
        addFilter(name, filter, false);
    }

    public void addFilter(String name, Filter filter, boolean init) {
        addFilter(name, filter, init, true);
    }

    public void createDefaultChain(String chainName) {
        // only create the defaultChain if we don't have a chain with this name already
        // (the global filters will already be in that chain)
        if (!getChainNames().contains(chainName) && !CollectionUtils.isEmpty(globalFilterNames)) {
            // add each of global filters
            globalFilterNames.stream().forEach(filterName -> addToChain(chainName, filterName));
        }
    }

    public void createChain(String chainName, String chainDefinition) {
        if (!StringUtils.hasText(chainName)) {
            throw new NullPointerException("chainName cannot be null or empty.");
        }
        if (!StringUtils.hasText(chainDefinition)) {
            throw new NullPointerException("chainDefinition cannot be null or empty.");
        }

        if (log.isDebugEnabled()) {
            log.debug("Creating chain [" + chainName + "] with global filters " + globalFilterNames + " and from String definition [" + chainDefinition + "]");
        }

        // first add each of global filters
        if (!CollectionUtils.isEmpty(globalFilterNames)) {
            globalFilterNames.stream().forEach(filterName -> addToChain(chainName, filterName));
        }

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
        String[] filterTokens = splitChainDefinition(chainDefinition);

        //each token is specific to each filter.
        //strip the name and extract any filter-specific config between brackets [ ]
        for (String token : filterTokens) {
            String[] nameConfigPair = toNameConfigPair(token);

            //now we have the filter name, path and (possibly null) path-specific config.  Let's apply them:
            addToChain(chainName, nameConfigPair[0], nameConfigPair[1]);
        }
    }

    /**
     * Splits the comma-delimited filter chain definition line into individual filter definition tokens.
     * <p/>
     * Example Input:
     * <pre>
     *     foo, bar[baz], blah[x, y]
     * </pre>
     * Resulting Output:
     * <pre>
     *     output[0] == foo
     *     output[1] == bar[baz]
     *     output[2] == blah[x, y]
     * </pre>
     * @param chainDefinition the comma-delimited filter chain definition.
     * @return an array of filter definition tokens
     * @since 1.2
     * @see <a href="https://issues.apache.org/jira/browse/SHIRO-205">SHIRO-205</a>
     */
    protected String[] splitChainDefinition(String chainDefinition) {
        return StringUtils.split(chainDefinition, StringUtils.DEFAULT_DELIMITER_CHAR, '[', ']', true, true);
    }

    /**
     * Based on the given filter chain definition token (e.g. 'foo' or 'foo[bar, baz]'), this will return the token
     * as a name/value pair, removing any brackets as necessary.  Examples:
     * <table>
     *     <tr>
     *         <th>Input</th>
     *         <th>Result</th>
     *     </tr>
     *     <tr>
     *         <td>{@code foo}</td>
     *         <td>returned[0] == {@code foo}<br/>returned[1] == {@code null}</td>
     *     </tr>
     *     <tr>
     *         <td>{@code foo[bar, baz]}</td>
     *         <td>returned[0] == {@code foo}<br/>returned[1] == {@code bar, baz}</td>
     *     </tr>
     * </table>
     * @param token the filter chain definition token
     * @return A name/value pair representing the filter name and a (possibly null) config value.
     * @throws ConfigurationException if the token cannot be parsed
     * @since 1.2
     * @see <a href="https://issues.apache.org/jira/browse/SHIRO-205">SHIRO-205</a>
     */
    protected String[] toNameConfigPair(String token) throws ConfigurationException {

        try {
            String[] pair = token.split("\\[", 2);
            String name = StringUtils.clean(pair[0]);

            if (name == null) {
                throw new IllegalArgumentException("Filter name not found for filter chain definition token: " + token);
            }
            String config = null;

            if (pair.length == 2) {
                config = StringUtils.clean(pair[1]);
                //if there was an open bracket, it assumed there is a closing bracket, so strip it too:
                config = config.substring(0, config.length() - 1);
                config = StringUtils.clean(config);

                //backwards compatibility prior to implementing SHIRO-205:
                //prior to SHIRO-205 being implemented, it was common for end-users to quote the config inside brackets
                //if that config required commas.  We need to strip those quotes to get to the interior quoted definition
                //to ensure any existing quoted definitions still function for end users:
                if (config != null && config.startsWith("\"") && config.endsWith("\"")) {
                    String stripped = config.substring(1, config.length() - 1);
                    stripped = StringUtils.clean(stripped);

                    //if the stripped value does not have any internal quotes, we can assume that the entire config was
                    //quoted and we can use the stripped value.
                    if (stripped != null && stripped.indexOf('"') == -1) {
                        config = stripped;
                    }
                    //else:
                    //the remaining config does have internal quotes, so we need to assume that each comma delimited
                    //pair might be quoted, in which case we need the leading and trailing quotes that we stripped
                    //So we ignore the stripped value.
                }
            }
            
            return new String[]{name, config};

        } catch (Exception e) {
            String msg = "Unable to parse filter chain definition token: " + token;
            throw new ConfigurationException(msg, e);
        }
    }

    protected void addFilter(String name, Filter filter, boolean init, boolean overwrite) {
        Filter existing = getFilter(name);
        if (existing == null || overwrite) {
            if (filter instanceof Nameable) {
                ((Nameable) filter).setName(name);
            }
            if (init) {
                initFilter(filter);
            }
            this.filters.put(name, filter);
        }
    }

    public void addToChain(String chainName, String filterName) {
        addToChain(chainName, filterName, null);
    }

    public void addToChain(String chainName, String filterName, String chainSpecificFilterConfig) {
        if (!StringUtils.hasText(chainName)) {
            throw new IllegalArgumentException("chainName cannot be null or empty.");
        }
        Filter filter = getFilter(filterName);
        if (filter == null) {
            throw new IllegalArgumentException("There is no filter with name '" + filterName +
                    "' to apply to chain [" + chainName + "] in the pool of available Filters.  Ensure a " +
                    "filter with that name/path has first been registered with the addFilter method(s).");
        }

        applyChainConfig(chainName, filter, chainSpecificFilterConfig);

        NamedFilterList chain = ensureChain(chainName);
        chain.add(filter);
    }

    public void setGlobalFilters(List<String> globalFilterNames) throws ConfigurationException {
        // validate each filter name
        if (!CollectionUtils.isEmpty(globalFilterNames)) {
            for (String filterName : globalFilterNames) {
                Filter filter = filters.get(filterName);
                if (filter == null) {
                    throw new ConfigurationException("There is no filter with name '" + filterName +
                                                     "' to apply to the global filters in the pool of available Filters.  Ensure a " +
                                                     "filter with that name/path has first been registered with the addFilter method(s).");
                }
                this.globalFilterNames.add(filterName);
            }
        }
    }

    protected void applyChainConfig(String chainName, Filter filter, String chainSpecificFilterConfig) {
        if (log.isDebugEnabled()) {
            log.debug("Attempting to apply path [" + chainName + "] to filter [" + filter + "] " +
                    "with config [" + chainSpecificFilterConfig + "]");
        }
        if (filter instanceof PathConfigProcessor) {
            ((PathConfigProcessor) filter).processPathConfig(chainName, chainSpecificFilterConfig);
        } else {
            if (StringUtils.hasText(chainSpecificFilterConfig)) {
                //they specified a filter configuration, but the Filter doesn't implement PathConfigProcessor
                //this is an erroneous config:
                String msg = "chainSpecificFilterConfig was specified, but the underlying " +
                        "Filter instance is not an 'instanceof' " +
                        PathConfigProcessor.class.getName() + ".  This is required if the filter is to accept " +
                        "chain-specific configuration.";
                throw new ConfigurationException(msg);
            }
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
     * Initializes the filter by calling <code>filter.init( {@link #getFilterConfig() getFilterConfig()} );</code>.
     *
     * @param filter the filter to initialize with the {@code FilterConfig}.
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

    protected void addDefaultFilters(boolean init) {
        for (DefaultFilter defaultFilter : DefaultFilter.values()) {
            addFilter(defaultFilter.name(), defaultFilter.newInstance(), init, false);
        }
    }
}
