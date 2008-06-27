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
package org.jsecurity.web.filter.authc;

import org.jsecurity.subject.Subject;
import static org.jsecurity.web.WebUtils.getSubject;
import org.jsecurity.web.filter.PathMatchingFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * <p>Filter that allows access to resources if the accessor is a known user, which is defined as
 * having a known principal.  This means that any user who is authenticated or remembered via a
 * 'remember me' feature will be allowed access from this filter.</p>
 *
 * @author Jeremy Haile
 * @since 0.9
 */
public class UserFilter extends PathMatchingFilter {

    @Override
    public boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        Subject subject = getSubject(request, response);

        // If principal is not null, then the user is known and should be allowed access.
        return subject.getPrincipal() != null;
    }
}
