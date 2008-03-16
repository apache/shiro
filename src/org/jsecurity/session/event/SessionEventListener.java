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
package org.jsecurity.session.event;

/**
 * Implemented by objects that wish to to be notified of events related to sessions.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public interface SessionEventListener {

    /**
     * Notification callback that something happened with a {@link org.jsecurity.session.Session Session}.
     * Implementations decide how to process the event (e.g. delegation, visitor pattern, etc).
     * @param event the event generated in response to something happening with a <tt>Session</tt>.
     */
    void onEvent( SessionEvent event );
    
}
