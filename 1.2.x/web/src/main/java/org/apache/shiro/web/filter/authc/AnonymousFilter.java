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
package org.apache.shiro.web.filter.authc;

import org.apache.shiro.web.filter.PathMatchingFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Filter that allows access to a path immeidately without performing security checks of any kind.
 * <p/>
 * This filter is useful primarily in exclusionary policies, where you have defined a url pattern
 * to require a certain security level, but maybe only subset of urls in that pattern should allow any access.
 * <p/>
 * For example, if you had a user-only section of a website, you might want to require that access to
 * any url in that section must be from an authenticated user.
 * <p/>
 * Here is how that would look in the IniShiroFilter configuration:
 * <p/>
 * <code>[urls]<br/>
 * /user/** = authc</code>
 * <p/>
 * But if you wanted <code>/user/signup/**</code> to be available to anyone, you have to exclude that path since
 * it is a subset of the first.  This is where the AnonymousFilter ('anon') is useful:
 * <p/>
 * <code>[urls]<br/>
 * /user/signup/** = anon<br/>
 * /user/** = authc</code>>
 * <p/>
 * Since the url pattern definitions follow a 'first match wins' paradigm, the <code>anon</code> filter will
 * match the <code>/user/signup/**</code> paths and the <code>/user/**</code> path chain will not be evaluated.
 *
 * @since 0.9
 */
public class AnonymousFilter extends PathMatchingFilter {

    /**
     * Always returns <code>true</code> allowing unchecked access to the underlying path or resource.
     *
     * @return <code>true</code> always, allowing unchecked access to the underlying path or resource.
     */
    @Override
    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) {
        // Always return true since we allow access to anyone
        return true;
    }

}
