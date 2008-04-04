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

import org.jsecurity.subject.PrincipalCollection;

/**
 * Event triggered when an authenticated subject (user, account, etc) logs out of the system.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class LogoutEvent extends AuthenticationEvent {

    private PrincipalCollection principals;

    /**
     * Creates a LogoutEvent for the specified subject logging out of the system.
     * @param principals the subject identifier(s) of the subject logging out.
     */
    public LogoutEvent( PrincipalCollection principals ) {
        super( principals );
        this.principals = principals;
    }

    /**
     * Creates a LogoutEvent for the specified subject logging out of the system, generated or caused by the
     * specified <tt>source</tt> argument.
     * @param source the component that generated or caused the event.
     * @param principals the subject identifier(s) of the subject logging out.
     */
    public LogoutEvent( Object source, PrincipalCollection principals ) {
        super(source);
        this.principals = principals;
    }

    public PrincipalCollection getPrincipals() {
        return principals;
    }
}
