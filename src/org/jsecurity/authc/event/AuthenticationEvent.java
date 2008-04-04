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
package org.jsecurity.authc.event;

import org.jsecurity.SecurityEvent;

/**
 * General event concerning the authentication of a particular Subject (aka User).
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public abstract class AuthenticationEvent extends SecurityEvent {

    /**
     * Creates a new <tt>AuthenticationEvent</tt>.
     * @param source the source of the event.
     */
    public AuthenticationEvent( Object source ) {
        super( source );
    }

}
