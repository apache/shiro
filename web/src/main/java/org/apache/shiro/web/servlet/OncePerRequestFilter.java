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
package org.apache.shiro.web.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;


/**
 * Filter base class that guarantees to be just executed once per request,
 * on any servlet container. It provides a {@link #doFilterInternal}
 * method with HttpServletRequest and HttpServletResponse arguments.
 * <p/>
 * The {@link #getAlreadyFilteredAttributeName} method determines how
 * to identify that a request is already filtered. The default implementation
 * is based on the configured name of the concrete filter instance.
 * <p/>
 * <b>NOTE</b> This class was borrowed from the Spring framework, and as such,
 * all copyright notices and author names have remained in tact.
 *
 * @since 0.1
 */
public abstract class OncePerRequestFilter extends NameableFilter {

    /**
     * Private internal log instance.
     */
    private static final Logger log = LoggerFactory.getLogger(OncePerRequestFilter.class);

    /**
     * Suffix that gets appended to the filter name for the "already filtered" request attribute.
     *
     * @see #getAlreadyFilteredAttributeName
     */
    public static final String ALREADY_FILTERED_SUFFIX = ".FILTERED";

    /**
     * This {@code doFilter} implementation stores a request attribute for
     * "already filtered", proceeding without filtering again if the
     * attribute is already there.
     *
     * @see #getAlreadyFilteredAttributeName
     * @see #shouldNotFilter
     * @see #doFilterInternal
     */
    public final void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String alreadyFilteredAttributeName = getAlreadyFilteredAttributeName();
        if (request.getAttribute(alreadyFilteredAttributeName) != null || shouldNotFilter(request)) {
            log.trace("Filter '{}' already executed.  Proceeding without invoking this filter.", getName());
            // Proceed without invoking this filter...
            filterChain.doFilter(request, response);
        } else {
            // Do invoke this filter...
            log.trace("Filter '{}' not yet executed.  Executing now.", getName());
            request.setAttribute(alreadyFilteredAttributeName, Boolean.TRUE);

            try {
                doFilterInternal(request, response, filterChain);
            } finally {
                // Once the request has finished, we're done and we don't
                // need to mark as 'already filtered' any more.
                request.removeAttribute(alreadyFilteredAttributeName);
            }
        }
    }

    /**
     * Return name of the request attribute that identifies that a request has already been filtered.
     * <p/>
     * The default implementation takes the configured {@link #getName() name} and appends &quot;{@code .FILTERED}&quot;.
     * If the filter is not fully initialized, it falls back to the implementation's class name.
     *
     * @return the name of the request attribute that identifies that a request has already been filtered.
     * @see #getName
     * @see #ALREADY_FILTERED_SUFFIX
     */
    protected String getAlreadyFilteredAttributeName() {
        String name = getName();
        if (name == null) {
            name = getClass().getName();
        }
        return name + ALREADY_FILTERED_SUFFIX;
    }

    /**
     * Can be overridden in subclasses for custom filtering control,
     * returning <code>true</code> to avoid filtering of the given request.
     * <p>The default implementation always returns <code>false</code>.
     *
     * @param request current HTTP request
     * @return whether the given request should <i>not</i> be filtered
     * @throws ServletException in case of errors
     */
    @SuppressWarnings({"UnusedDeclaration"})
    protected boolean shouldNotFilter(ServletRequest request) throws ServletException {
        return false;
    }


    /**
     * Same contract as for
     * {@link #doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)},
     * but guaranteed to be invoked only once per request.
     *
     * @param request  incoming {@code ServletRequest}
     * @param response outgoing {@code ServletResponse}
     * @param chain    the {@code FilterChain} to execute
     * @throws ServletException if there is a problem processing the request
     * @throws IOException      if there is an I/O problem processing the request
     */
    protected abstract void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
            throws ServletException, IOException;
}
