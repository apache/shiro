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

import org.jsecurity.web.filter.PathMatchingFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * <p>Filter that grants access to a resource regardless of whether they are authenticated, remembered, or
 * completely unknown.  Essentially if this filter is applied to a resource, any user can access it.</p>
 *
 * <p>This filter is intended to be used as an exclusionary measure only, since the default behavior of the
 * {@link org.jsecurity.web.servlet.JSecurityFilter} is to grant anonymous access.  So for example if
 * a web application restricted access to <tt>/myapp/**</tt> to authenticated users but wanted to have one URL
 * <tt>/myapp/checkMeOut</tt> to be available for anyone, the anonymous filter could be applied to that
 * URL prior to an authentication filter to exclude it from requiring authenticated access.</p>

 *
 * @author Jeremy Haile
 * @since 0.9
 */
public class AnonymousFilter extends PathMatchingFilter {

    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) {
        // Always return true since we allow access to anyone
        return true;
     }

}
