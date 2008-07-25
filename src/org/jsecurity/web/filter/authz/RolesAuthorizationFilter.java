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
package org.jsecurity.web.filter.authz;

import org.jsecurity.subject.Subject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.Set;

/**
 * Filter that allows access if the current user has the roles specified by the mapped value, or denies access
 * if the user does not have all of the roles specified.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.9
 */
public class RolesAuthorizationFilter extends AuthorizationFilter {

    @SuppressWarnings({"unchecked"})
    public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException {

        Subject subject = getSubject(request, response);
        Set<String> roles = (Set<String>) mappedValue;

        boolean hasRoles = true;
        if (roles != null && !roles.isEmpty()) {
            if (roles.size() == 1) {
                if (!subject.hasRole(roles.iterator().next())) {
                    hasRoles = false;
                }
            } else {
                if (!subject.hasAllRoles(roles)) {
                    hasRoles = false;
                }
            }
        }

        return hasRoles;
    }

}
