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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.util.ThreadState;
import org.apache.shiro.web.DefaultWebSecurityManager;
import org.apache.shiro.web.WebSecurityManager;
import org.apache.shiro.web.WebUtils;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.shiro.web.subject.support.WebSubjectThreadState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Abstract base class that provides all standard Shiro request filtering behavior and expects
 * subclasses to implement configuration-specific logic (INI, XML, .properties, etc).
 * <p/>
 * Subclasses should perform configuration and construction logic in an overridden
 * {@link #init()} method implementation.  That implementation should make available any constructed
 * {@code SecurityManager} and {@code FilterChainResolver} by calling
 * {@link #setSecurityManager(org.apache.shiro.web.WebSecurityManager)} and
 * {@link #setFilterChainResolver(org.apache.shiro.web.filter.mgt.FilterChainResolver)} methods respectively.
 *
 * @since 1.0
 */
public abstract class AbstractShiroFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AbstractShiroFilter.class);

    // Reference to the security manager used by this filter
    private WebSecurityManager securityManager;

    // Used to determine which chain should handle an incoming request/response
    private FilterChainResolver filterChainResolver;

    protected AbstractShiroFilter() {
    }

    public WebSecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager(WebSecurityManager sm) {
        this.securityManager = sm;
    }

    public FilterChainResolver getFilterChainResolver() {
        return filterChainResolver;
    }

    public void setFilterChainResolver(FilterChainResolver filterChainResolver) {
        this.filterChainResolver = filterChainResolver;
    }

    protected final void onFilterConfigSet() throws Exception {
        init();
        ensureSecurityManager();
    }

    public void init() throws Exception {
    }

    /**
     * A fallback mechanism called in {@link #onFilterConfigSet()} to ensure that the
     * {@link #getSecurityManager() securityManager} property has been set by configuration, and if not,
     * creates one automatically.
     */
    private void ensureSecurityManager() {
        WebSecurityManager securityManager = getSecurityManager();
        if (securityManager == null) {
            log.info("No SecurityManager configured.  Creating default.");
            securityManager = createDefaultSecurityManager();
            setSecurityManager(securityManager);
        }
    }

    protected WebSecurityManager createDefaultSecurityManager() {
        return new DefaultWebSecurityManager();
    }

    protected boolean isHttpSessions() {
        return getSecurityManager().isHttpSessionMode();
    }

    /**
     * Wraps the original HttpServletRequest in a {@link ShiroHttpServletRequest}, which is required for supporting
     * Servlet Specification behavior backed by a {@link org.apache.shiro.subject.Subject Subject} instance.
     *
     * @param orig the original Servlet Container-provided incoming {@code HttpServletRequest} instance.
     * @return {@link ShiroHttpServletRequest ShiroHttpServletRequest} instance wrapping the original.
     * @since 1.0
     */
    protected ServletRequest wrapServletRequest(HttpServletRequest orig) {
        return new ShiroHttpServletRequest(orig, getServletContext(), isHttpSessions());
    }

    /**
     * Prepares the {@code ServletRequest} instance that will be passed to the {@code FilterChain} for request
     * processing.
     * <p/>
     * If the {@code ServletRequest} is an instance of {@link HttpServletRequest}, the value returned from this method
     * is obtained by calling {@link #wrapServletRequest(javax.servlet.http.HttpServletRequest)} to allow Shiro-specific
     * HTTP behavior, otherwise the original {@code ServletRequest} argument is returned.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @param chain    the Servlet Container provided {@code FilterChain} that will receive the returned request.
     * @return the {@code ServletRequest} instance that will be passed to the {@code FilterChain} for request processing.
     * @since 1.0
     */
    @SuppressWarnings({"UnusedDeclaration"})
    protected ServletRequest prepareServletRequest(ServletRequest request, ServletResponse response, FilterChain chain) {
        ServletRequest toUse = request;
        if (request instanceof HttpServletRequest) {
            HttpServletRequest http = (HttpServletRequest) request;
            toUse = wrapServletRequest(http);
        }
        return toUse;
    }

    /**
     * Returns a new {@link ShiroHttpServletResponse} instance, wrapping the {@code orig} argument, in order to provide
     * correct URL rewriting behavior required by the Servlet Specification when using Shiro-based sessions (and not
     * Servlet Container HTTP-based sessions).
     *
     * @param orig    the original {@code HttpServletResponse} instance provided by the Servlet Container.
     * @param request the {@code ShiroHttpServletRequest} instance wrapping the original request.
     * @return the wrapped ServletResponse instance to use during {@link FilterChain} execution.
     * @since 1.0
     */
    protected ServletResponse wrapServletResponse(HttpServletResponse orig, ShiroHttpServletRequest request) {
        return new ShiroHttpServletResponse(orig, getServletContext(), request);
    }

    /**
     * Prepares the {@code ServletResponse} instance that will be passed to the {@code FilterChain} for request
     * processing.
     * <p/>
     * This implementation delegates to {@link #wrapServletRequest(javax.servlet.http.HttpServletRequest)}
     * only if Shiro-based sessions are enabled (that is, !{@link #isHttpSessions()}) and the request instance is a
     * {@link ShiroHttpServletRequest}.  This ensures that any URL rewriting that occurs is handled correctly using the
     * Shiro-managed Session's sessionId and not a servlet container session ID.
     * <p/>
     * If HTTP-based sessions are enabled (the default), then this method does nothing and just returns the
     * {@code ServletResponse} argument as-is, relying on the default Servlet Container URL rewriting logic.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @param chain    the Servlet Container provided {@code FilterChain} that will receive the returned request.
     * @return the {@code ServletResponse} instance that will be passed to the {@code FilterChain} during request processing.
     * @since 1.0
     */
    @SuppressWarnings({"UnusedDeclaration"})
    protected ServletResponse prepareServletResponse(ServletRequest request, ServletResponse response, FilterChain chain) {
        ServletResponse toUse = response;
        if (!isHttpSessions() && (request instanceof ShiroHttpServletRequest) &&
                (response instanceof HttpServletResponse)) {
            //the ShiroHttpServletResponse exists to support URL rewriting for session ids.  This is only needed if
            //using Shiro sessions (i.e. not simple HttpSession based sessions):
            toUse = wrapServletResponse((HttpServletResponse) response, (ShiroHttpServletRequest) request);
        }
        return toUse;
    }

    /**
     * Binds the current request/response pair and additional information to a thread-local to be made available to Shiro
     * during the course of the request/response process.  This implementation binds the request/response pair and
     * any associated Subject (and its relevant thread-based data) via a {@link org.apache.shiro.web.subject.support.WebSubjectThreadState}.  That
     * threadState is returned so it can be used during thread cleanup at the end of the request.
     * <p/>
     * To guarantee properly cleaned threads in a thread-pooled Servlet Container environment, the corresponding
     * {@link #unbind} method must be called in a {@code finally} block to ensure that the thread remains clean even
     * in the event of an exception thrown while processing the request.  This class's
     * {@link #doFilterInternal(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)}
     * method implementation does indeed function this way.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @return ThreadStateManager the thread state used to bind necessary state for the request execution.
     * @since 1.0
     */
    protected ThreadState bind(ServletRequest request, ServletResponse response) {
        ThreadContext.bind(getSecurityManager());
        WebUtils.bind(request);
        WebUtils.bind(response);
        WebSubject subject = new WebSubject.Builder(getSecurityManager(), request, response).buildWebSubject();
        ThreadState threadState = new WebSubjectThreadState(subject);
        threadState.bind();
        return threadState;
    }

    /**
     * Unbinds (removes out of scope) the current {@code ServletRequest} and {@link ServletResponse}.
     * <p/>
     * This method implementation merely clears <em>all</em> thread state by calling
     * {@link org.apache.shiro.subject.support.SubjectThreadState#clear()} to guarantee
     * that <em>everything</em> that might have been bound to the thread by Shiro has been removed to ensure the
     * underlying Thread may be safely re-used in a thread-pooled Servlet Container environment.
     *
     * @param threadState the web thread state created when the request and response first were initiated.
     * @since 1.0
     */
    @SuppressWarnings({"UnusedDeclaration"})
    protected void unbind(ThreadState threadState) {
        if ( threadState != null ) {
            threadState.clear();
        }
        //just for good measure (SHIRO-159):
        ThreadContext.clear();
    }

    /**
     * Updates any 'native'  Session's last access time that might exist to the timestamp when this method is called.
     * If native sessions are not enabled (that is, standard Servlet container sessions are being used) or there is no
     * session ({@code subject.getSession(false) == null}), this method does nothing.
     * <p/>This method implementation merely calls
     * <code>Session.{@link org.apache.shiro.session.Session#touch() touch}()</code> on the session.
     *
     * @param request  incoming request - ignored, but available to subclasses that might wish to override this method
     * @param response outgoing response - ignored, but available to subclasses that might wish to override this method
     * @since 1.0
     */
    @SuppressWarnings({"UnusedDeclaration"})
    protected void updateSessionLastAccessTime(ServletRequest request, ServletResponse response) {
        if (!isHttpSessions()) { //'native' sessions
            Subject subject = SecurityUtils.getSubject();
            //Subject should never _ever_ be null, but just in case:
            if (subject != null) {
                Session session = subject.getSession(false);
                if (session != null) {
                    try {
                        session.touch();
                    } catch (Throwable t) {
                        log.error("session.touch() method invocation has failed.  Unable to update" +
                                "the corresponding session's last access time based on the incoming request.", t);
                    }
                }
            }
        }
    }

    /**
     * {@code doFilterInternal} implementation that sets-up, executes, and cleans-up a Shiro-filtered request.  It
     * performs the following ordered operations:
     * <ol>
     * <li>{@link #prepareServletRequest(ServletRequest, ServletResponse, FilterChain) Prepares}
     * the incoming {@code ServletRequest} for use during Shiro's processing</li>
     * <li>{@link #prepareServletResponse(ServletRequest, ServletResponse, FilterChain) Prepares}
     * the outgoing {@code ServletResponse} for use during Shiro's processing</li>
     * <li>{@link #bind(ServletRequest,ServletResponse) Binds} the request/response pair
     * and associated data to the currently executing thread for use during processing</li>
     * <li>{@link #updateSessionLastAccessTime(javax.servlet.ServletRequest, javax.servlet.ServletResponse) Updates}
     * any associated session's {@link org.apache.shiro.session.Session#getLastAccessTime() lastAccessTime} to ensure
     * session timeouts are honored</li>
     * <li>{@link #executeChain(ServletRequest,ServletResponse,FilterChain) Executes}
     * the appropriate {@code FilterChain}</li>
     * <li>{@link #unbind(org.apache.shiro.util.ThreadState) Unbinds} the request/response
     * pair and any other associated data from the thread.
     * </ul>
     * <p/>
     * The {@link #unbind(org.apache.shiro.util.ThreadState) unbind} method is called in a
     * {@code finally} block to guarantee the thread may be cleanly re-used in a thread-pooled Servlet Container
     * environment.
     *
     * @param servletRequest  the incoming {@code ServletRequest}
     * @param servletResponse the outgoing {@code ServletResponse}
     * @param chain           the container-provided {@code FilterChain} to execute
     * @throws javax.servlet.ServletException if an error occurs
     * @throws IOException                    if an IO error occurs
     */
    protected void doFilterInternal(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
            throws ServletException, IOException {

        ServletRequest request = prepareServletRequest(servletRequest, servletResponse, chain);
        ServletResponse response = prepareServletResponse(request, servletResponse, chain);

        ThreadState threadState = null;

        try {
            threadState = bind(request, response);
            updateSessionLastAccessTime(request, response);
            executeChain(request, response, chain);
        } finally {
            unbind(threadState);
        }
    }

    /**
     * Returns the {@code FilterChain} to execute for the given request.
     * <p/>
     * The {@code origChain} argument is the
     * original {@code FilterChain} supplied by the Servlet Container, but it may be modified to provide
     * more behavior by pre-pending further chains according to the Shiro configuration.
     * <p/>
     * This implementation returns the chain that will actually be executed by acquiring the chain from a
     * {@link #getFilterChainResolver() filterChainResolver}.  The resolver determines exactly which chain to
     * execute, typically based on URL configuration.  If no chain is returned from the resolver call
     * (returns {@code null}), then the {@code origChain} will be returned by default.
     *
     * @param request   the incoming ServletRequest
     * @param response  the outgoing ServletResponse
     * @param origChain the original {@code FilterChain} provided by the Servlet Container
     * @return the {@link FilterChain} to execute for the given request
     * @since 1.0
     */
    protected FilterChain getExecutionChain(ServletRequest request, ServletResponse response, FilterChain origChain) {
        FilterChain chain = origChain;

        FilterChainResolver resolver = getFilterChainResolver();
        if (resolver == null) {
            log.debug("No FilterChainResolver configured.  Returning original FilterChain.");
            return origChain;
        }

        FilterChain resolved = resolver.getChain(request, response, origChain);
        if (resolved != null) {
            log.trace("Resolved a configured FilterChain for the current request.");
            chain = resolved;
        } else {
            log.trace("No FilterChain configured for the current request.  Using the default.");
        }

        return chain;
    }

    /**
     * Executes a {@link FilterChain} for the given request.
     * <p/>
     * This implementation first delegates to
     * <code>{@link #getExecutionChain(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain) getExecutionChain}</code>
     * to allow the application's Shiro configuration to determine exactly how the chain should execute.  The resulting
     * value from that call is then executed directly by calling the returned {@code FilterChain}'s
     * {@link FilterChain#doFilter doFilter} method.  That is:
     * <pre>
     * FilterChain chain = {@link #getExecutionChain}(request, response, origChain);
     * chain.{@link FilterChain#doFilter doFilter}(request,response);</pre>
     *
     * @param request   the incoming ServletRequest
     * @param response  the outgoing ServletResponse
     * @param origChain the Servlet Container-provided chain that may be wrapped further by an application-configured
     *                  chain of Filters.
     * @throws IOException      if the underlying {@code chain.doFilter} call results in an IOException
     * @throws ServletException if the underlying {@code chain.doFilter} call results in a ServletException
     * @since 1.0
     */
    protected void executeChain(ServletRequest request, ServletResponse response, FilterChain origChain)
            throws IOException, ServletException {
        FilterChain chain = getExecutionChain(request, response, origChain);
        chain.doFilter(request, response);
    }
}
