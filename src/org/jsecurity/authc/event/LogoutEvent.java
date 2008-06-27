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
package org.jsecurity.authc.event;

import org.jsecurity.subject.PrincipalCollection;

/**
 * Event triggered when an authenticated subject (user, account, etc) logs out of the system.
 *
 * @author Les Hazlewood
 * @since 0.1
 */
public class LogoutEvent extends AuthenticationEvent {

    /**
     * The principals of the Subject logging out.
     */
    private PrincipalCollection principals;

    /**
     * Creates a LogoutEvent for the Subject logging out of the system.
     *
     * @param principals the subject identifier(s) of the subject logging out.
     */
    public LogoutEvent(PrincipalCollection principals) {
        super(principals);
        this.principals = principals;
    }

    /**
     * Creates a LogoutEvent for the Subject logging out of the system, generated or caused by the
     * specified <tt>source</tt> argument.
     *
     * @param source     the component that generated or caused the event.
     * @param principals the subject identifier(s) of the subject logging out.
     */
    public LogoutEvent(Object source, PrincipalCollection principals) {
        super(source);
        this.principals = principals;
    }

    /**
     * The identifier(s) of the Subject logging out.
     *
     * @return the identifier(s) of the Subject logging out.
     */
    public PrincipalCollection getPrincipals() {
        return principals;
    }
}
