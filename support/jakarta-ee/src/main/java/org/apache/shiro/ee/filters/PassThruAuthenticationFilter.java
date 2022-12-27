/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.ee.filters;

import org.apache.shiro.ee.filters.AuthenticationFilterDelegate.MethodsFromFilter;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import lombok.experimental.Delegate;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;

/**
 * Implements JSF Ajax redirection via OmniFaces
 * Implements form resubmit and auto remember-me functionality
 */
@Slf4j
public class PassThruAuthenticationFilter extends org.apache.shiro.web.filter.authc.PassThruAuthenticationFilter {
    private final @Delegate AuthenticationFilterDelegate delegate;

    private class Methods implements MethodsFromFilter {
        @Override
        public Subject getSubject(ServletRequest request, ServletResponse response) {
            return PassThruAuthenticationFilter.super.getSubject(request, response);
        }

        @Override
        public boolean isLoginRequest(ServletRequest request, ServletResponse response) {
            return PassThruAuthenticationFilter.super.isLoginRequest(request, response);
        }

        @Override
        public boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                ServletRequest request, ServletResponse response) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getLoginUrl() {
            return PassThruAuthenticationFilter.super.getLoginUrl();
        }

        @Override
        public boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
            return PassThruAuthenticationFilter.super.preHandle(request, response);
        }
    };

    public PassThruAuthenticationFilter() {
        delegate = new AuthenticationFilterDelegate(new Methods());
    }
}
