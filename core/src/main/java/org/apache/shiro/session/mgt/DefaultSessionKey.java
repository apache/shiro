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
package org.apache.shiro.session.mgt;

import java.io.Serializable;

/**
 * Default implementation of the {@link SessionKey} interface, which allows setting and retrieval of a concrete
 * {@link #getSessionId() sessionId} that the {@code SessionManager} implementation can use to look up a
 * {@code Session} instance.
 *
 * @since 1.0
 */
public class DefaultSessionKey implements SessionKey, Serializable {

    private Serializable sessionId;

    public DefaultSessionKey() {
    }

    public DefaultSessionKey(Serializable sessionId) {
        this.sessionId = sessionId;
    }

    public void setSessionId(Serializable sessionId) {
        this.sessionId = sessionId;
    }

    public Serializable getSessionId() {
        return this.sessionId;
    }
}
