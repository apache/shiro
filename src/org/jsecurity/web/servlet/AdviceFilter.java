/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
     * Default implementation that always returns <code>true</code> that can be overridden by subclasses
     * for specific preHandle request continuation logic.
     */
    public boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        return true;
    }

    /**
     * Default implementation that does nothing and exists only as a template hook for subclasses that
     * wish to implement postHandle logic.
     */
    public void postHandle(ServletRequest request, ServletResponse response) throws Exception {
    }

    /**
     * Default implementation that does nothing and exists only as a template hook for subclasses that
     * wish to implement afterCompletion logic.
     */
    public void afterCompletion(ServletRequest request, ServletResponse response, Exception exception) throws Exception {
    }

    protected void executeChain(ServletRequest request, ServletResponse response, FilterChain chain) throws Exception {
        chain.doFilter(request, response);
    }

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
