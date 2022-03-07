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
package org.apache.shiro.session.mgt;

import org.apache.shiro.util.MapContext;
import org.apache.shiro.lang.util.StringUtils;

import java.io.Serializable;
import java.util.Map;

/**
 * Default implementation of the {@link SessionContext} interface which provides getters and setters that
 * wrap interaction with the underlying backing context map.
 *
 * @since 1.0
 */
public class DefaultSessionContext extends MapContext implements SessionContext {

    private static final long serialVersionUID = -1424160751361252966L;

    private static final String HOST = DefaultSessionContext.class.getName() + ".HOST";
    private static final String SESSION_ID = DefaultSessionContext.class.getName() + ".SESSION_ID";

    public DefaultSessionContext() {
        super();
    }

    public DefaultSessionContext(Map<String, Object> map) {
        super(map);
    }

    public String getHost() {
        return getTypedValue(HOST, String.class);
    }

    public void setHost(String host) {
        if (StringUtils.hasText(host)) {
            put(HOST, host);
        }
    }

    public Serializable getSessionId() {
        return getTypedValue(SESSION_ID, Serializable.class);
    }

    public void setSessionId(Serializable sessionId) {
        nullSafePut(SESSION_ID, sessionId);
    }
}
