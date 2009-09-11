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

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import java.util.Set;

/**
 * @since 1.0
 */
public interface FilterChainManager {

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
     */
    void addToChain(String chainName, String filterName, String chainSpecificFilterConfig);
}
