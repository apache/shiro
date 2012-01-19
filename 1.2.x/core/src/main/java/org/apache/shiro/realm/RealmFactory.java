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
package org.apache.shiro.realm;

import java.util.Collection;

/**
 * Enables Shiro end-users to configure and initialize one or more {@link Realm Realm} instances
 * in any manner desired.
 * <p/>
 * This interface exists to support environments where end-users may not wish to use Shiro's default
 * text-based configuration to create and configure realms, and instead wish to retrieve a realm configured in a
 * proprietary manner.  An implementation of this interface can access that proprietary mechanism to retrieve the
 * already-created <tt>Realm</tt>s.
 *
 * <p>The <code>Realm</code> instances returned will used to construct the application's
 * {@link org.apache.shiro.mgt.SecurityManager SecurityManager} instance.
 *
 * @since 0.9
 */
public interface RealmFactory {

    /**
     * Returns a collection of {@link Realm Realm} instances that will be used to construct
     * the application's SecurityManager instance.
     *
     * <p>The order of the collection is important.  The {@link org.apache.shiro.mgt.SecurityManager SecurityManager}
     * implementation will consult the Realms during authentication (log-in) and authorization (access control)
     * operations in the collection's <b>iteration order</b>.  That is, the resulting collection's
     * {@link java.util.Iterator Iterator} determines the order in which Realms are used.
     *
     * @return the <code>Collection</code> of Realms that the application's <code>SecurityManager</code> will use
     *         for security data access.
     */
    Collection<Realm> getRealms();

}
