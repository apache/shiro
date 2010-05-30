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
package org.apache.shiro.web.session.mgt;

import org.apache.shiro.session.mgt.DefaultSessionContext;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.Map;

/**
 * Default implementation of the {@link WebSessionContext} interface which provides getters and setters that
 * wrap interaction with the underlying backing context map.
 *
 * @since 1.0
 */
public class DefaultWebSessionContext extends DefaultSessionContext implements WebSessionContext {

    private static final long serialVersionUID = -3974604687792523072L;

    private static final String SERVLET_REQUEST = DefaultWebSessionContext.class.getName() + ".SERVLET_REQUEST";
    private static final String SERVLET_RESPONSE = DefaultWebSessionContext.class.getName() + ".SERVLET_RESPONSE";

    public DefaultWebSessionContext() {
        super();
    }

    public DefaultWebSessionContext(Map<String, Object> map) {
        super(map);
    }

    public void setServletRequest(ServletRequest request) {
        if (request != null) {
            put(SERVLET_REQUEST, request);
        }
    }

    public ServletRequest getServletRequest() {
        return getTypedValue(SERVLET_REQUEST, ServletRequest.class);
    }

    public void setServletResponse(ServletResponse response) {
        if (response != null) {
            put(SERVLET_RESPONSE, response);
        }
    }

    public ServletResponse getServletResponse() {
        return getTypedValue(SERVLET_RESPONSE, ServletResponse.class);
    }
}
