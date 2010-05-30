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
package org.apache.shiro.authc;

import org.apache.shiro.subject.PrincipalCollection;

/**
 * An SPI interface allowing cleanup logic to be executed during logout of a previously authenticated Subject/user.
 *
 * <p>As it is an SPI interface, it is really intended for SPI implementors such as those implementing Realms.
 *
 * <p>All of Shiro's concrete Realm implementations implement this interface as a convenience for those wishing
 * to subclass them.
 *
 * @since 0.9
 */
public interface LogoutAware {

    /**
     * Callback triggered when a <code>Subject</code> logs out of the system.
     *
     * @param principals the identifying principals of the Subject logging out.
     */
    public void onLogout(PrincipalCollection principals);
}
