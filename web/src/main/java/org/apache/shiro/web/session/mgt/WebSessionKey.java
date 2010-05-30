/*
 * Copyright 2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.web.session.mgt;

import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.web.util.RequestPairSource;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.Serializable;

/**
 * A {@link org.apache.shiro.session.mgt.SessionKey SessionKey} implementation that also retains the
 * {@code ServletRequest} and {@code ServletResponse} associated with the web request that is performing the
 * session lookup.
 *
 * @since 1.0
 */
public class WebSessionKey extends DefaultSessionKey implements RequestPairSource {

    private final ServletRequest servletRequest;
    private final ServletResponse servletResponse;

    public WebSessionKey(ServletRequest request, ServletResponse response) {
        if (request == null) {
            throw new NullPointerException("request argument cannot be null.");
        }
        if (response == null) {
            throw new NullPointerException("response argument cannot be null.");
        }
        this.servletRequest = request;
        this.servletResponse = response;
    }

    public WebSessionKey(Serializable sessionId, ServletRequest request, ServletResponse response) {
        this(request, response);
        setSessionId(sessionId);
    }

    public ServletRequest getServletRequest() {
        return servletRequest;
    }

    public ServletResponse getServletResponse() {
        return servletResponse;
    }
}
