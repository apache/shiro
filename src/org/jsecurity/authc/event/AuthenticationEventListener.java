/*
 * Copyright 2005-2008 Jeremy Haile, Les Hazlewood
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

/**
 * Listener interface implemented by objects that wish to be notified of
 * {@link AuthenticationEvent}s.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public interface AuthenticationEventListener {

    /**
     * Notification callback that something occured during an authentication attempt.  Implementations decide how to
     * process the event (e.g. delegation, visitor pattern, etc).
     * @param event the event generated during the authentication attempt.
     */
    void onEvent( AuthenticationEvent event );

}

