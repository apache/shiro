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
package org.jsecurity.session;

import java.io.Serializable;

/**
 * Exception thrown when a {@link #getOriginalSessionId() referenced session} has been determined to be invalid and
 * a new session was created automatically to replace it.  This exception is thrown if the {@code SessionManager} has
 * been configured to auto-recreate sessions when it encounters an invalid session reference.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class ReplacedSessionException extends InvalidSessionException {

    private Serializable newSessionId = null;

    public ReplacedSessionException() {
        super();
    }

    public ReplacedSessionException(String msg, Throwable cause, Serializable originalSessionId, Serializable newSessionId) {
        super(msg, cause, originalSessionId);
        this.newSessionId = newSessionId;
    }

    public Serializable getOriginalSessionId() {
        return super.getSessionId();
    }

    public Serializable getNewSessionId() {
        return newSessionId;
    }
}
