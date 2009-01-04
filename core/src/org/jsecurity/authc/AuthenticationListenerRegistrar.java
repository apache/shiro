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
package org.jsecurity.authc;

import java.util.Collection;

/**
 * An <code>AuthenticationListenerRegistrar</code> is a component that is capable of registering interested
 * {@link AuthenticationListener AuthenticationListener}s that wish to be notified during the authentication
 * process.
 * <p/>
 * This interface only guarantees that registered listeners will be notified during the authentication process.
 * How that notification occurs is implementation specific (e.g. iteration over a collection, JMS, etc.).
 * 
 * @author Les Hazlewood
 * @since 0.9
 */
public interface AuthenticationListenerRegistrar {

    /**
     * Sets the <code>AuthenticationListener</code>(s) that wish to be notified during the
     * authentication process.
     * @param listeners one or more <code>AuthenticationListener</code>s that should be notified during the
     * authentication process.
     */
    void setAuthenticationListeners(Collection<AuthenticationListener> listeners);

    /**
     * Registeres a single <code>listener</code> that wishes to be notified during the authentication process.
     * @param listener the single <code>listener</code> that wishes to be notified during the authentication process.
     */
    void add(AuthenticationListener listener);

    /**
     * Removes a single <code>listener</code> that no longer wishes to be notified during the authentication process.
     * @param listener the single <code>listener</code> that no longer wishes to be notified during the authentication process.
     * @return <code>true</code> if the listener was removed (i.e. it was previously registered), or <code>false</code>
     * if the listener was not removed (i.e. it wasn't registered yet, effectively a no-op).
     */
    boolean remove(AuthenticationListener listener);
}
