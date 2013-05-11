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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.subject.support.DefaultWebSubjectContext;
import org.apache.shiro.web.util.RequestPairSource;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * A {@code WebSubject} represents a Subject instance that was acquired as a result of an incoming
 * {@link ServletRequest}.
 *
 * @since 1.0
 */
public interface WebSubject extends Subject, RequestPairSource {

    /**
     * Returns the {@code ServletRequest} accessible when the Subject instance was created.
     *
     * @return the {@code ServletRequest} accessible when the Subject instance was created.
     */
    ServletRequest getServletRequest();

    /**
     * Returns the {@code ServletResponse} accessible when the Subject instance was created.
     *
     * @return the {@code ServletResponse} accessible when the Subject instance was created.
     */
    ServletResponse getServletResponse();

    /**
     * A {@code WebSubject.Builder} performs the same function as a {@link Subject.Builder Subject.Builder}, but
     * additionally ensures that the Servlet request/response pair that is triggering the Subject instance's creation
     * is retained for use by internal Shiro components as necessary.
     */
    public static class Builder extends Subject.Builder {

        /**
         * Constructs a new {@code Web.Builder} instance using the {@link SecurityManager SecurityManager} obtained by
         * calling {@code SecurityUtils.}{@link SecurityUtils#getSecurityManager() getSecurityManager()}.  If you want
         * to specify your own SecurityManager instance, use the
         * {@link #Builder(SecurityManager, ServletRequest, ServletResponse)} constructor instead.
         *
         * @param request  the incoming ServletRequest that will be associated with the built {@code WebSubject} instance.
         * @param response the outgoing ServletRequest paired with the ServletRequest that will be associated with the
         *                 built {@code WebSubject} instance.
         */
        public Builder(ServletRequest request, ServletResponse response) {
            this(SecurityUtils.getSecurityManager(), request, response);
        }

        /**
         * Constructs a new {@code Web.Builder} instance using the specified {@code SecurityManager} instance to
         * create the {@link WebSubject WebSubject} instance.
         *
         * @param securityManager the {@code SecurityManager SecurityManager} instance to use to build the
         *                        {@code WebSubject} instance.
         * @param request         the incoming ServletRequest that will be associated with the built {@code WebSubject}
         *                        instance.
         * @param response        the outgoing ServletRequest paired with the ServletRequest that will be associated
         *                        with the built {@code WebSubject} instance.
         */
        public Builder(SecurityManager securityManager, ServletRequest request, ServletResponse response) {
            super(securityManager);
            if (request == null) {
                throw new IllegalArgumentException("ServletRequest argument cannot be null.");
            }
            if (response == null) {
                throw new IllegalArgumentException("ServletResponse argument cannot be null.");
            }
            setRequest(request);
            setResponse(response);
        }

        /**
         * Overrides the parent implementation to return a new instance of a
         * {@link DefaultWebSubjectContext DefaultWebSubjectContext} to account for the additional request/response
         * pair.
         *
         * @return a new instance of a {@link DefaultWebSubjectContext DefaultWebSubjectContext} to account for the
         *         additional request/response pair.
         */
        @Override
        protected SubjectContext newSubjectContextInstance() {
            return new DefaultWebSubjectContext();
        }

        /**
         * Called by the {@code WebSubject.Builder} constructor, this method places the request object in the
         * context map for later retrieval.
         *
         * @param request the incoming ServletRequest that triggered the creation of the {@code WebSubject} instance.
         * @return 'this' for method chaining.
         */
        protected Builder setRequest(ServletRequest request) {
            if (request != null) {
                ((WebSubjectContext) getSubjectContext()).setServletRequest(request);
            }
            return this;
        }

        /**
         * Called by the {@code WebSubject.Builder} constructor, this method places the response object in the
         * context map for later retrieval.
         *
         * @param response the outgoing ServletRequest paired with the ServletRequest that triggered the creation of
         *                 the {@code WebSubject} instance.
         * @return 'this' for method chaining.
         */
        protected Builder setResponse(ServletResponse response) {
            if (response != null) {
                ((WebSubjectContext) getSubjectContext()).setServletResponse(response);
            }
            return this;
        }

        /**
         * Returns {@link #buildSubject() super.buildSubject()}, but additionally ensures that the returned instance
         * is an {@code instanceof} {@link WebSubject WebSubject} and to support a type-safe method so a caller
         * does not have to cast.   Per the parent class's method JavaDoc, this method will return a new instance
         * each time it is called.
         *
         * @return a new {@link WebSubject WebSubject} instance built by this {@code Builder}.
         */
        public WebSubject buildWebSubject() {
            Subject subject = super.buildSubject();
            if (!(subject instanceof WebSubject)) {
                String msg = "Subject implementation returned from the SecurityManager was not a " +
                        WebSubject.class.getName() + " implementation.  Please ensure a Web-enabled SecurityManager " +
                        "has been configured and made available to this builder.";
                throw new IllegalStateException(msg);
            }
            return (WebSubject) subject;
        }
    }

}
