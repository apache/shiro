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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.util.LifecycleUtils;
import org.jsecurity.web.interceptor.WebInterceptor;

import javax.servlet.*;
import java.io.IOException;

/**
 * A <tt>WebInterceptorFilter</tt> is a Servlet Filter that merely delegates all filter operations to a single internally
 * wrapped {@link org.jsecurity.web.interceptor.WebInterceptor} instance.  It is a simple utility class to cleanly use a
 * <tt>WebInterceptor</tt> as a servlet filter if so desired - the benefit is that you only have to code one
 * WebInterceptor class, and you can re-use it in multiple environments such as in a servlet container,
 * in Spring or Pico, JBoss, etc.  This Filter represents the mechanism to use that one WebInterceptor directly in a
 * Servlet environment.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class WebInterceptorFilter implements Filter {

    protected final transient Log log = LogFactory.getLog(getClass());

    protected WebInterceptor webInterceptor;

    public WebInterceptor getWebInterceptor() {
        return this.webInterceptor;
    }

    public void setWebInterceptor(WebInterceptor webInterceptor) {
        this.webInterceptor = webInterceptor;
    }

    public void doFilter( ServletRequest request, ServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        Exception exception = null;

        WebInterceptor interceptor = getWebInterceptor();

        try {

            boolean continueChain = interceptor.preHandle(request, response);
            if (log.isTraceEnabled()) {
                log.trace("Invked interceptor.preHandle method.  Continuing chain?: [" + continueChain + "]");
            }

            if (continueChain) {
                chain.doFilter(request,response);
            }

            interceptor.postHandle(request, response);
            if (log.isTraceEnabled()) {
                log.trace("Successfully invoked interceptor.postHandle method");
            }

        } catch (Exception e) {
            exception = e;
        } finally {
            try {
                interceptor.afterCompletion(request, response, exception);
                if (log.isTraceEnabled()) {
                    log.trace("Successfully invoked interceptor.afterCompletion method.");
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
                    String msg = "Filter execution resulted in a Exception " +
                            "(not IOException or ServletException as the Filter api recommends).  " +
                            "Wrapping in ServletException and propagating.";
                    throw new ServletException(msg, exception);
                }
            }
        }
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        WebInterceptor interceptor = getWebInterceptor();
        if (interceptor == null) {
            throw new IllegalStateException("WebInterceptor property must be set.");
        }
    }

    public void destroy() {
        LifecycleUtils.destroy(getWebInterceptor());
    }
}
