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

import org.apache.shiro.authz.Permission;

import java.util.Collection;

/**
 * A RolePermissionResolver resolves a String value and converts it into a Collection of
 * {@link org.apache.shiro.authz.Permission} instances.
 * <p/>
 * In some cases a {@link org.apache.shiro.realm.Realm} my only be able to return a list of roles.  This
 * component allows an application to resolve the roles into permissions.
 *
 */
public interface RolePermissionResolver {

    /**
     * Resolves a Collection of Permissions based on the given String representation.
     *
     * @param roleString the String representation of a role name to resolve.
     * @return a Collection of Permissions based on the given String representation.
     */
    Collection<Permission> resolvePermissionsInRole(String roleString);

}
