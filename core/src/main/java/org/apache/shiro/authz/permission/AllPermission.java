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
package org.apache.shiro.authz.permission;

import java.io.Serializable;

import org.apache.shiro.authz.Permission;


/**
 * An all <tt>AllPermission</tt> instance is one that always implies any other permission; that is, its
 * {@link #implies implies} method always returns <tt>true</tt>.
 *
 * <p>You should be very careful about the users, roles, and/or groups to which this permission is assigned since
 * those respective entities will have the ability to do anything.  As such, an instance of this class
 * is typically only assigned only to "root" or "administrator" users or roles.
 *
 * @since 0.1
 */
public class AllPermission implements Permission, Serializable {

    /**
     * Always returns <tt>true</tt>, indicating any Subject granted this permission can do anything.
     *
     * @param p the Permission to check for implies logic.
     * @return <tt>true</tt> always, indicating any Subject grated this permission can do anything.
     */
    public boolean implies(Permission p) {
        return true;
    }
}
