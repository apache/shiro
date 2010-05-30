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
package org.apache.shiro.web.subject;

import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.util.RequestPairSource;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * A {@code WebSubjectContext} is a {@link SubjectContext} that additionally provides for type-safe
 * methods to set and retrieve a {@link ServletRequest} and {@link ServletResponse}.
 *
 * @since 1.0
 */
public interface WebSubjectContext extends SubjectContext, RequestPairSource {

    /**
     * Returns the {@code ServletRequest} received by the servlet container triggering the creation of the
     * {@code Subject} instance.
     *
     * @return the {@code ServletRequest} received by the servlet container triggering the creation of the
     *         {@code Subject} instance.
     */
    ServletRequest getServletRequest();

    /**
     * Sets the {@code ServletRequest} received by the servlet container triggering the creation of the
     * {@code Subject} instance.
     *
     * @param request the {@code ServletRequest} received by the servlet container triggering the creation of the
     *                {@code Subject} instance.
     */
    void setServletRequest(ServletRequest request);

    ServletRequest resolveServletRequest();

    /**
     * The paired {@code ServletResponse} corresponding to the associated {@link #getServletRequest servletRequest}.
     *
     * @return the paired {@code ServletResponse} corresponding to the associated
     *         {@link #getServletRequest servletRequest}.
     */
    ServletResponse getServletResponse();

    /**
     * Sets the paired {@code ServletResponse} corresponding to the associated {@link #getServletRequest servletRequest}.
     *
     * @param response The paired {@code ServletResponse} corresponding to the associated
     *                 {@link #getServletRequest servletRequest}.
     */
    void setServletResponse(ServletResponse response);

    ServletResponse resolveServletResponse();
}
