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
package org.apache.shiro.web.jaxrs;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

/**
 * A Shiro based {@link SecurityContext} that exposes the current Shiro {@link Subject} as a {@link Principal}.
 * The {@link #isUserInRole(String)} method returns the result of {@link Subject#hasRole(String)}.
 *
 * @since 1.4
 */
public class ShiroSecurityContext implements SecurityContext {

    final private ContainerRequestContext containerRequestContext;
    final private SecurityContext originalSecurityContext;

    public ShiroSecurityContext(ContainerRequestContext containerRequestContext) {
        this.containerRequestContext = containerRequestContext;
        this.originalSecurityContext = containerRequestContext.getSecurityContext();
    }

    @Override
    public Principal getUserPrincipal() {

        Principal result;

        Subject subject = getSubject();
        PrincipalCollection shiroPrincipals = subject.getPrincipals();
        if (shiroPrincipals != null) {
            result = shiroPrincipals.oneByType(Principal.class);

            if (result == null) {
                result = new ObjectPrincipal(shiroPrincipals.getPrimaryPrincipal());
            }
        }
        else {
            result = originalSecurityContext.getUserPrincipal();
        }

        return result;
    }

    @Override
    public boolean isUserInRole(String role) {
        return getSubject().hasRole(role);
    }

    @Override
    public boolean isSecure() {
        return containerRequestContext.getSecurityContext().isSecure();
    }

    @Override
    public String getAuthenticationScheme() {
        return containerRequestContext.getSecurityContext().getAuthenticationScheme();
    }

    private Subject getSubject() {
        return SecurityUtils.getSubject();
    }


    /**
     * Java Principal wrapper around any Shiro Principal object.s
     */
    private class ObjectPrincipal implements Principal {
        private Object object = null;

        public ObjectPrincipal(Object object) {
            this.object = object;
        }

        public Object getObject() {
            return object;
        }

        public String getName() {
            return getObject().toString();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            ObjectPrincipal that = (ObjectPrincipal) o;

            return object.equals(that.object);

        }

        public int hashCode() {
            return object.hashCode();
        }

        public String toString() {
            return object.toString();
        }
    }
}
