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

import org.apache.shiro.lang.util.Nameable;

import javax.servlet.FilterConfig;

/**
 * Allows a filter to be named via JavaBeans-compatible
 * {@link #getName()}/{@link #setName(String)} methods.  If no name is specified, the name of the filter will
 * default to the name given to it in {@code web.xml} (the {@code FilterConfig}'s
 * {@link javax.servlet.FilterConfig#getFilterName() filterName}).
 *
 * @since 1.0
 */
public abstract class NameableFilter extends AbstractFilter implements Nameable {

    /**
     * The name of this filter, unique within an application.
     */
    private String name;

    /**
     * Returns the filter's name.
     * <p/>
     * Unless overridden by calling the {@link #setName(String) setName(String)} method, this value defaults to the
     * filter name as specified by the servlet container at start-up:
     * <pre>
     * this.name = {@link #getFilterConfig() getFilterConfig()}.{@link javax.servlet.FilterConfig#getFilterName() getName()};</pre>
     *
     * @return the filter name, or {@code null} if none available
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
     * servlet container at start-up:
     * <pre>
     * this.name = {@link #getFilterConfig() getFilterConfig()}.{@link javax.servlet.FilterConfig#getFilterName() getName()};</pre>
     *
     * @param name the name of the filter.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Returns a StringBuilder instance with the {@link #getName() name}, or if the name is {@code null}, just the
     * {@code super.toStringBuilder()} instance.
     *
     * @return a StringBuilder instance to use for appending String data that will eventually be returned from a
     *         {@code toString()} invocation.
     */
    protected StringBuilder toStringBuilder() {
        String name = getName();
        if (name == null) {
            return super.toStringBuilder();
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append(name);
            return sb;
        }
    }

}
