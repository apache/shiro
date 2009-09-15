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

import org.apache.shiro.util.Nameable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import java.io.IOException;


/**
 * Filter base class that guarantees to be just executed once per request,
 * on any servlet container. It provides a {@link #doFilterInternal}
 * method with HttpServletRequest and HttpServletResponse arguments.
 * <p/>
 * <p>The {@link #getAlreadyFilteredAttributeName} method determines how
 * to identify that a request is already filtered. The default implementation
 * is based on the configured name of the concrete filter instance.
 * <p/>
 * <p><b>NOTE</b> This class was borrowed from the Spring framework, and as such,
 * all copyright notices and author names have remained in tact.
 *
 * @author Les Hazlewood
 * @author Juergen Hoeller
 * @since 0.1
 */
public abstract class OncePerRequestFilter extends ServletContextSupport implements Filter, Nameable {

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
     * FilterConfig provided by the Servlet container at startup.
     */
    protected FilterConfig filterConfig;

    /**
     * The name of this filter, unique within an application.
     */
    private String name;

    /**
     * Returns the servlet container specified <code>FilterConfig</code> instance provided at
     * {@link #init(javax.servlet.FilterConfig) startup}.
     *
     * @return the servlet container specified <code>FilterConfig</code> instance provided at startup.
     */
    public FilterConfig getFilterConfig() {
        return filterConfig;
    }

    /**
     * Sets the FilterConfig <em>and</em> the <code>ServletContext</code> as attributes of this class for use by
     * subclasses.  That is:
     * <p/>
     * <code>this.filterConfig = filterConfig;<br/>
     * setServletContext(filterConfig.getServletContext());</code>
     *
     * @param filterConfig the FilterConfig instance provided by the Servlet container at startup.
     */
    public void setFilterConfig(FilterConfig filterConfig) {
        this.filterConfig = filterConfig;
        setServletContext(filterConfig.getServletContext());
    }

    /**
     * Returns the name of this filter.
     * <p/>
     * Unless overridden by calling the {@link #setName(String) setName(String)} method, this value defaults to the
     * filter name as specified by the servlet container at startup:
     * <p/>
     * <code>this.name = {@link #getFilterConfig() getFilterConfig()}.{@link FilterConfig#getFilterName() getName()};</code>
     *
     * @return the filter name, or <code>null</code> if none available
     * @see javax.servlet.GenericServlet#getServletName()
     * @see javax.servlet.FilterConfig#getFilterName()
     */
    protected String getName() {
        if (this.name == null) {
            FilterConfig config = getFilterConfig();
            if (config != null) {
                this.name = config.getFilterName();
            }
        }

        return this.name;
    }

    /**
     * Sets the filter's name.
     * <p/>
     * Unless overridden by calling this method, this value defaults to the filter name as specified by the
     * servlet container at startup:
     * <p/>
     * <code>this.name = {@link #getFilterConfig() getFilterConfig()}.{@link FilterConfig#getFilterName() getName()};</code>
     *
     * @param name the name of the filter.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Sets the filter's {@link #setFilterConfig filterConfig} and then immediately calls
     * {@link #onFilterConfigSet() onFilterConfigSet()} to trigger any processing a subclass might wish to perform.
     *
     * @param filterConfig the servlet container supplied FilterConfig instance.
     * @throws ServletException if {@link #onFilterConfigSet() onFilterConfigSet()} throws an Exception.
     */
    public final void init(FilterConfig filterConfig) throws ServletException {
        setFilterConfig(filterConfig);
        try {
            onFilterConfigSet();
        } catch (Exception e) {
            if (e instanceof ServletException) {
                throw (ServletException) e;
            } else {
                if (log.isErrorEnabled()) {
                    log.error("Unable to start Filter: [" + e.getMessage() + "].", e);
                }
                throw new ServletException(e);
            }
        }
    }

    /**
     * Template method to be overridden by subclasses to perform initialization logic at startup.  The
     * <code>ServletContext</code> and <code>FilterConfig</code> will be accessible
     * (and non-<code>null</code>) at the time this method is invoked via the
     * {@link #getServletContext() getServletContext()} and {@link #getFilterConfig() getFilterConfig()}
     * methods respectively.
     *
     * @throws Exception if the subclass has an error upon initialization.
     */
    protected void onFilterConfigSet() throws Exception {
    }

    /**
     * This <code>doFilter</code> implementation stores a request attribute for
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
            doFilterInternal(request, response, filterChain);
        }
    }

    /**
     * Return name of the request attribute that identifies that a request has already been filtered.
     * <p/>
     * The default implementation takes the configured {@link #getName() name} and appends ".FILTERED".
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
     * Same contract as for <code>doFilter</code>, but guaranteed to be just invoked once per request.
     *
     * @param request  incoming {@code ServletRequest}
     * @param response outgoing {@code ServletResponse}
     * @param chain    the {@code FilterChain} to execute
     * @throws ServletException if there is a problem processing the request
     * @throws IOException      if there is an IO problem processing the request
     */
    protected abstract void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
            throws ServletException, IOException;

    /**
     * Default no-op implementation that can be overridden by subclasses for custom cleanup behavior.
     */
    public void destroy() {
    }

    /**
     * It is highly recommended not to override this method directly, and instead override the
     * {@link #toStringBuilder() toStringBuilder()} method, a better-performing alternative.
     *
     * @return the String representation of this instance.
     */
    @Override
    public String toString() {
        return toStringBuilder().toString();
    }

    /**
     * Same concept as {@link #toString() toString()}, but returns a {@link StringBuilder} instance instead.
     * Overriding subclasses would usually call <code>super.toStringBuilder()</code> and use the returned instance
     * to append to instead of creating a new StringBuilder.
     *
     * @return a StringBuilder instance to use for appending String data that will eventually be returned from a
     *         {@code toString()} invocation.
     */
    protected StringBuilder toStringBuilder() {
        StringBuilder sb = new StringBuilder();
        String name = getName();
        if (name == null) {
            sb.append(super.toString());
        } else {
            sb.append(name);
        }
        return sb;
    }
}
