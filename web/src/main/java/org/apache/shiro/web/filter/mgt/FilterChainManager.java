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

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import java.util.Map;
import java.util.Set;

/**
 * A {@code FilterChainManager} manages the creation and modification of {@link Filter} chains from an available pool
 * of {@link Filter} instances.
 *
 * @since 1.0
 */
public interface FilterChainManager {

    /**
     * Returns the pool of available {@code Filter}s managed by this manager, keyed by {@code name}.
     *
     * @return the pool of available {@code Filter}s managed by this manager, keyed by {@code name}.
     */
    Map<String, Filter> getFilters();

    /**
     * Returns the filter chain identified by the specified {@code chainName} or {@code null} if there is no chain with
     * that name.
     *
     * @param chainName the name identifying the filter chain.
     * @return the filter chain identified by the specified {@code chainName} or {@code null} if there is no chain with
     *         that name.
     */
    NamedFilterList getChain(String chainName);

    /**
     * Returns {@code true} if one or more configured chains are available, {@code false} if none are configured.
     *
     * @return {@code true} if one or more configured chains are available, {@code false} if none are configured.
     */
    boolean hasChains();

    /**
     * Returns the names of all configured chains or an empty {@code Set} if no chains have been configured.
     *
     * @return the names of all configured chains or an empty {@code Set} if no chains have been configured.
     */
    Set<String> getChainNames();

    /**
     * Proxies the specified {@code original} FilterChain with the named chain.  The returned
     * {@code FilterChain} instance will first execute the configured named chain and then lastly invoke the given
     * {@code original} chain.
     *
     * @param original  the original FilterChain to proxy
     * @param chainName the name of the internal configured filter chain that should 'sit in front' of the specified
     *                  original chain.
     * @return a {@code FilterChain} instance that will execute the named chain and then finally the
     *         specified {@code original} FilterChain instance.
     * @throws IllegalArgumentException if there is no configured chain with the given {@code chainName}.
     */
    FilterChain proxy(FilterChain original, String chainName);

    /**
     * Adds a filter to the 'pool' of available filters that can be used when
     * {@link #addToChain(String, String, String) creating filter chains}.
     * <p/>
     * Calling this method is effectively the same as calling
     * <code>{@link #addFilter(String, javax.servlet.Filter, boolean) addFilter}(name, filter, <b>true</b>);</code>
     *
     * @param name   the name to assign to the filter, used to reference the filter in chain definitions
     * @param filter the filter to initialize and then add to the pool of available filters that can be used
     */
    void addFilter(String name, Filter filter);

    /**
     * Adds a filter to the 'pool' of available filters that can be used when
     * {@link #addToChain(String, String, String) creating filter chains}.
     *
     * @param name   the name to assign to the filter, used to reference the filter in chain definitions
     * @param filter the filter to assign to the filter pool
     * @param init   whether or not the {@code Filter} should be
     *               {@link Filter#init(javax.servlet.FilterConfig) initialized} first before being added to the pool.
     */
    void addFilter(String name, Filter filter, boolean init);

    /**
     * Creates a filter chain for the given {@code chainName} with the specified {@code chainDefinition}
     * String.
     * <h3>Conventional Use</h3>
     * Because the {@code FilterChainManager} interface does not impose any restrictions on filter chain names,
     * (it expects only Strings), a convenient convention is to make the chain name an actual URL path expression
     * (such as an {@link org.apache.shiro.util.AntPathMatcher Ant path expression}).  For example:
     * <p/>
     * <code>createChain(<b><em>path_expression</em></b>, <em>path_specific_filter_chain_definition</em>);</code>
     * This convention can be used by a {@link FilterChainResolver} to inspect request URL paths
     * against the chain name (path) and, if a match is found, return the corresponding chain for runtime filtering.
     * <h3>Chain Definition Format</h3>
     * The {@code chainDefinition} method argument is expected to conform to the following format:
     * <pre>
     * filter1[optional_config1], filter2[optional_config2], ..., filterN[optional_configN]</pre>
     * where
     * <ol>
     * <li>{@code filterN} is the name of a filter previously
     * {@link #addFilter(String, javax.servlet.Filter) registered} with the manager, and</li>
     * <li>{@code [optional_configN]} is an optional bracketed string that has meaning for that particular filter for
     * <em>this particular chain</em></li>
     * </ol>
     * If the filter does not need specific config for that chain name/URL path,
     * you may discard the brackets - that is, {@code filterN[]} just becomes {@code filterN}.
     * <p/>
     * And because this method does create a chain, remember that order matters!  The comma-delimited filter tokens in
     * the {@code chainDefinition} specify the chain's execution order.
     * <h3>Examples</h3>
     * <pre>/account/** = authcBasic</pre>
     * This example says &quot;Create a filter named '{@code /account/**}' consisting of only the '{@code authcBasic}'
     * filter&quot;.  Also because the {@code authcBasic} filter does not need any path-specific
     * config, it doesn't have any config brackets {@code []}.
     * <p/>
     * <pre>/remoting/** = authcBasic, roles[b2bClient], perms[&quot;remote:invoke:wan,lan&quot;]</pre>
     * This example by contrast uses the 'roles' and 'perms' filters which <em>do</em> use bracket notation.  This
     * definition says:
     * <p/>
     * Construct a filter chain named '{@code /remoting/**}' which
     * <ol>
     * <li>ensures the user is first authenticated ({@code authcBasic}) then</li>
     * <li>ensures that user has the {@code b2bClient} role, and then finally</li>
     * <li>ensures that they have the {@code remote:invoke:lan,wan} permission.</li>
     * </ol>
     * <p/>
     * <b>Note</b>: because elements within brackets [ ] can be comma-delimited themselves, you must quote the
     * internal bracket definition if commas are needed (the above example has 'lan,wan').  If we didn't do that, the
     * parser would interpret the chain definition as four tokens:
     * <ol>
     * <li>authcBasic</li>
     * <li>roles[b2bclient]</li>
     * <li>perms[remote:invoke:lan</li>
     * <li>wan]</li>
     * </ol>
     * which is obviously incorrect.  So remember to use quotes if your internal bracket definitions need to use commas.
     *
     * @param chainName       the name to associate with the chain, conventionally a URL path pattern.
     * @param chainDefinition the string-formatted chain definition used to construct an actual
     *                        {@link NamedFilterList} chain instance.
     * @see FilterChainResolver
     * @see org.apache.shiro.util.AntPathMatcher AntPathMatcher
     */
    void createChain(String chainName, String chainDefinition);

    /**
     * Adds (appends) a filter to the filter chain identified by the given {@code chainName}.  If there is no chain
     * with the given name, a new one is created and the filter will be the first in the chain.
     *
     * @param chainName  the name of the chain where the filter will be appended.
     * @param filterName the name of the {@link #addFilter registered} filter to add to the chain.
     * @throws IllegalArgumentException if there is not a {@link #addFilter(String, javax.servlet.Filter) registered}
     *                                  filter under the given {@code filterName}
     */
    void addToChain(String chainName, String filterName);

    /**
     * Adds (appends) a filter to the filter chain identified by the given {@code chainName}.  If there is no chain
     * with the given name, a new one is created and the filter will be the first in the chain.
     * <p/>
     * Note that the final argument expects the associated filter to be an instance of
     * a {@link org.apache.shiro.web.filter.PathConfigProcessor PathConfigProcessor} to accept per-chain configuration.
     * If it is not, a {@link IllegalArgumentException} will be thrown.
     *
     * @param chainName                 the name of the chain where the filter will be appended.
     * @param filterName                the name of the {@link #addFilter registered} filter to add to the chain.
     * @param chainSpecificFilterConfig the filter-specific configuration that should be applied for only the specified
     *                                  filter chain.
     * @throws IllegalArgumentException if there is not a {@link #addFilter(String, javax.servlet.Filter) registered}
     *                                  filter under the given {@code filterName}
     * @throws ConfigurationException   if the filter is not capable of accepting {@code chainSpecificFilterConfig}
     *                                  (usually such filters implement the
     *                                  {@link org.apache.shiro.web.filter.PathConfigProcessor PathConfigProcessor}
     *                                  interface).
     */
    void addToChain(String chainName, String filterName, String chainSpecificFilterConfig) throws ConfigurationException;
}
