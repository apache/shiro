/*
 * Copyright 2002-2008 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.web.servlet;

import org.jsecurity.util.Nameable;

import javax.servlet.*;
import java.io.IOException;

/**
 * Filter base class that guarantees to be just executed once per request,
 * on any servlet container. It provides a {@link #doFilterInternal}
 * method with HttpServletRequest and HttpServletResponse arguments.
 *
 * <p>The {@link #getAlreadyFilteredAttributeName} method determines how
 * to identify that a request is already filtered. The default implementation
 * is based on the configured name of the concrete filter instance.
 *
 * <p><b>NOTE</b> This class was borrowed from the Spring framework, and as such,
 * all copyright notices and author names have remained in tact.
 *
 * @author Juergen Hoeller
 * @since 06.12.2003
 */
public abstract class OncePerRequestFilter extends ServletContextSupport implements Filter, Nameable {

    /**
     * Suffix that gets appended to the filter name for the
     * "already filtered" request attribute.
     *
     * @see #getAlreadyFilteredAttributeName
     */
    public static final String ALREADY_FILTERED_SUFFIX = ".FILTERED";

    protected FilterConfig filterConfig = null;

    private String name = null;

    public FilterConfig getFilterConfig() {
        return filterConfig;
    }

    /**
     * Sets the FilterConfig <em>and</em> the <code>filterConfig.getServletContext()</code> as
     * attributes of this class for use by subclasses.
     *
     * @param filterConfig the FilterConfig instance provided by the Servlet container at startup.
     */
    public void setFilterConfig(FilterConfig filterConfig) {
        this.filterConfig = filterConfig;
        setServletContext(filterConfig.getServletContext());
    }

    /**
     * Make the name of this filter available to subclasses.
     * <p>Takes the FilterConfig's filter name by default.
     * If initialized as bean in a Spring application context,
     * it falls back to the bean name as defined in the bean factory.
     *
     * @return the filter name, or <code>null</code> if none available
     * @see javax.servlet.GenericServlet#getServletName()
     * @see javax.servlet.FilterConfig#getFilterName()
     */
    protected String getName() {
        if (this.name == null) {
            if (this.filterConfig != null) {
                this.name = this.filterConfig.getFilterName();
            }
        }

        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

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
            if (log.isTraceEnabled()) {
                log.trace("Filter already executed.  Proceeding without invoking this filter.");
            }
            // Proceed without invoking this filter...
            filterChain.doFilter(request, response);
        } else {
            // Do invoke this filter...
            if (log.isTraceEnabled()) {
                log.trace("Filter not yet executed.  Executing now.");
            }
            request.setAttribute(alreadyFilteredAttributeName, Boolean.TRUE);
            doFilterInternal(request, response, filterChain);
        }
    }

    /**
     * Return the name of the request attribute that identifies that a request
     * is already filtered.
     * <p>Default implementation takes the configured name of the concrete filter
     * instance and appends ".FILTERED". If the filter is not fully initialized,
     * it falls back to its class name.
     *
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
    protected boolean shouldNotFilter(ServletRequest request) throws ServletException {
        return false;
    }


    /**
     * Same contract as for <code>doFilter</code>, but guaranteed to be
     * just invoked once per request. Provides HttpServletRequest and
     * HttpServletResponse arguments instead of the default ServletRequest
     * and ServletResponse ones.
     */
    protected abstract void doFilterInternal(
            ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws ServletException, IOException;

    public void destroy() {
    }
}
