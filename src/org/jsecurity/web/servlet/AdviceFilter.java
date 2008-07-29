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
package org.jsecurity.web.servlet;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

/**
 * A Servlet Filter that enables AOP-style advice for a SerlvetRequest via
 * {@link #preHandle(javax.servlet.ServletRequest, javax.servlet.ServletResponse) preHandle},
 * {@link #postHandle(javax.servlet.ServletRequest, javax.servlet.ServletResponse) postHandle},
 * and {@link #afterCompletion(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Exception) afterCompletion}
 * hooks.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class AdviceFilter extends OncePerRequestFilter {

    /**
     * Returns <code>true</code> if the filter chain should be allowed to continue, <code>false</code> otherwise.
     * Called before the chain is actually consulted/executed.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @return <code>true</code> if the filter chain should be allowed to continue, <code>false</code> otherwise.
     * @throws Exception if there is any error.
     */
    public boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        return true;
    }

    /**
     * Allows 'post' advice logic to be called, but only if no exception occurs during filter chain execution.  That
     * is, if {@link #executeChain executeChain} throws an exception, this method will never be called.  Be aware of
     * this when implementing logic.  Most resource 'cleanup' behavior is often done in the
     * {@link #afterCompletion(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Exception) afterCompletion(request,response,exception)}
     * implementation, which is guaranteed to be called for every request, even when the chain processing throws
     * an Exception.
     * <p/>
     * The default implementation is a no-op, and exists as a template method for subclasses.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @throws Exception if an error occurs.
     */
    public void postHandle(ServletRequest request, ServletResponse response) throws Exception {
    }

    /**
     * Called in all cases in a <code>finally</code> block even if {@link #preHandle preHandle} returns
     * <code>false</code> or if an exception is thrown during filter chain processing.  Can be used for resource
     * cleanup if so desired.
     * <p/>
     * The default implementation is a no-op, and exists as a template method for subclasses.
     *
     * @param request   the incoming ServletRequest
     * @param response  the outgoing ServletResponse
     * @param exception any exception thrown during {@link #preHandle preHandle}, {@link #executeChain executeChain},
     *                  or {@link #postHandle postHandle} execution, or <code>null</code> if no exception was thrown
     *                  (i.e. the chain processed successfully).
     * @throws Exception if an error occurs.
     */
    public void afterCompletion(ServletRequest request, ServletResponse response, Exception exception) throws Exception {
    }

    /**
     * Actually executes the specified filter chain by calling
     * <pre>chain.doFilter(request,response);</pre>
     * Can be overridden by subclasses for custom logic.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @param chain    the filter chain to execute
     * @throws Exception if there is any error executing the chain.
     */
    protected void executeChain(ServletRequest request, ServletResponse response, FilterChain chain) throws Exception {
        chain.doFilter(request, response);
    }

    /**
     * Actually implements the chain execution logic, utilizing pre, post, and after advice hooks.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @param chain    the filter chain to execute
     * @throws ServletException if a servlet-related error occurs
     * @throws IOException      if an IO error occurs
     */
    @SuppressWarnings({"ThrowFromFinallyBlock"})
    public void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        Exception exception = null;

        try {

            boolean continueChain = preHandle(request, response);
            if (log.isTraceEnabled()) {
                log.trace("Invked preHandle method.  Continuing chain?: [" + continueChain + "]");
            }

            if (continueChain) {
                executeChain(request, response, chain);
            }

            postHandle(request, response);
            if (log.isTraceEnabled()) {
                log.trace("Successfully invoked postHandle method");
            }

        } catch (Exception e) {
            exception = e;
        } finally {
            try {
                afterCompletion(request, response, exception);
                if (log.isTraceEnabled()) {
                    log.trace("Successfully invoked afterCompletion method.");
                }
            } catch (Exception e) {
                if (exception == null) {
                    exception = e;
                }
            }
            if (exception != null) {
                if (exception instanceof ServletException) {
                    throw (ServletException) exception;
                } else if (exception instanceof IOException) {
                    throw (IOException) exception;
                } else {
                    String msg = "Filter execution resulted in an unexpected Exception " +
                            "(not IOException or ServletException as the Filter api recommends).  " +
                            "Wrapping in ServletException and propagating.";
                    throw new ServletException(msg, exception);
                }
            }
        }
    }
}
