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

import javax.servlet.ServletContext;

/**
 * Base implementation for any components that need to access the web application's {@link ServletContext ServletContext}.
 *
 * @since 0.2
 */
public class ServletContextSupport {

    //TODO - complete JavaDoc
    private ServletContext servletContext = null;

    public ServletContext getServletContext() {
        return servletContext;
    }

    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    protected String getContextInitParam(String paramName) {
        return getServletContext().getInitParameter(paramName);
    }

    private ServletContext getRequiredServletContext() {
        ServletContext servletContext = getServletContext();
        if (servletContext == null) {
            String msg = "ServletContext property must be set via the setServletContext method.";
            throw new IllegalStateException(msg);
        }
        return servletContext;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    protected void setContextAttribute(String key, Object value) {
        if (value == null) {
            removeContextAttribute(key);
        } else {
            getRequiredServletContext().setAttribute(key, value);
        }
    }

    @SuppressWarnings({"UnusedDeclaration"})
    protected Object getContextAttribute(String key) {
        return getRequiredServletContext().getAttribute(key);
    }

    protected void removeContextAttribute(String key) {
        getRequiredServletContext().removeAttribute(key);
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
     *
     * @return a StringBuilder instance to use for appending String data that will eventually be returned from a
     *         {@code toString()} invocation.
     */
    protected StringBuilder toStringBuilder() {
        return new StringBuilder(super.toString());
    }
}
