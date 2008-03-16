/*
 * Copyright 2005-2008 Les Hazlewood
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
package org.jsecurity.authc.event.mgt;

import org.jsecurity.authc.event.AuthenticationEventListener;

import java.util.Collection;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public interface AuthenticationEventListenerRegistrar {
    void setAuthenticationEventListeners( Collection<AuthenticationEventListener> listeners );
    void add( AuthenticationEventListener listener );
    boolean remove( AuthenticationEventListener listener );
}
