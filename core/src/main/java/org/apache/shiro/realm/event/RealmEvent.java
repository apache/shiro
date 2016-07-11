/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.apache.shiro.realm.event;

import org.apache.shiro.subject.PrincipalCollection;

/**
 * Base class for events publish from within Realm classes.
 *
 * If you want to listen for all Realm events you can register a class that contains a method similar to:
 * <pre>
 *     @org.apache.shiro.event.Subscribe
 *     public void onEvent(RealmEvent realmEvent) {
 *         // do something with event here.
 *     }
 * </pre>
 *
 * or You can listen for a specific event, for example:
 * <pre>
 *     @org.apache.shiro.event.Subscribe
 *     public void onEvent(AuthenticationEvent realmEvent) {
 *         // do something with event here.
 *     }
 * </pre>
 *
 * @since 1.3
 * @see AuthenticationEvent
 * @see AuthenticationFailureEvent
 * @see org.apache.shiro.event.EventBus
 */
public abstract class RealmEvent {

    private String realmName;
    private PrincipalCollection principalCollection;
    private boolean cached;

    private RealmEvent(String realmName) {
        this.realmName = realmName;
    }

    private RealmEvent(String realmName, PrincipalCollection principalCollection, boolean cached) {
        this(realmName);
        this.principalCollection = principalCollection;
        this.cached = cached;
    }

    public String getRealmName() {
        return realmName;
    }

    public PrincipalCollection getPrincipalCollection() {
        return principalCollection;
    }

    public boolean isCached() {
        return cached;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        RealmEvent that = (RealmEvent) o;

        if (cached != that.cached) return false;
        if (realmName != null ? !realmName.equals(that.realmName) : that.realmName != null) return false;
        return principalCollection != null ? principalCollection.equals(that.principalCollection) : that.principalCollection == null;

    }

    @Override
    public int hashCode() {
        int result = realmName != null ? realmName.hashCode() : 0;
        result = 31 * result + (principalCollection != null ? principalCollection.hashCode() : 0);
        result = 31 * result + (cached ? 1 : 0);
        return result;
    }


    /**
     * Event that is published when a authentication attempt is successful.
     * 
     * @since 1.3
     */
    public static class AuthenticationEvent extends RealmEvent {

        public AuthenticationEvent(String realmName, PrincipalCollection principalCollection, boolean cached) {
            super(realmName, principalCollection, cached);
        }
    }


    /**
     * Event that is published when an authentication attempt failed.
     *
     * @since 1.3
     */
    public final static class AuthenticationFailureEvent extends RealmEvent {

        private Exception failureException;

        public AuthenticationFailureEvent(String realmName) {
            super(realmName);
        }

        public AuthenticationFailureEvent(String realmName, Exception failureException) {
            super(realmName);
            failureException = failureException;
        }

        public Exception getFailureException() {
            return failureException;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            if (!super.equals(o)) return false;

            AuthenticationFailureEvent that = (AuthenticationFailureEvent) o;

            return failureException != null ? failureException.equals(that.failureException) : that.failureException == null;

        }

        @Override
        public int hashCode() {
            int result = super.hashCode();
            result = 31 * result + (failureException != null ? failureException.hashCode() : 0);
            return result;
        }
    }


}
