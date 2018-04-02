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


/**
 * <tt>PermissionResolver</tt> implementation that returns a new {@link WildcardPermission WildcardPermission}
 * based on the input string.
 *
 * @since 0.9
 */
public class WildcardPermissionResolver implements PermissionResolver {
    boolean caseSensitive;
    
    /**
     * Constructor to specify case sensitivity for the resolved premissions.
     * @param caseSensitive true if permissions should be case sensitive.
     */
    public WildcardPermissionResolver(boolean caseSensitive) {
        this.caseSensitive=caseSensitive;
    }

    /**
     * Default constructor. 
     * Equivalent to calling WildcardPermissionResolver(false)
     * 
     * @see WildcardPermissionResolver#WildcardPermissionResolver(boolean)
     */
    public WildcardPermissionResolver() {
        this(WildcardPermission.DEFAULT_CASE_SENSITIVE);
    }

    /**
     * Set the case sensitivity of the resolved Wildcard permissions.
     * @param state the caseSensitive flag state for resolved permissions.
     */
    public void setCaseSensitive(boolean state) {
        this.caseSensitive = state;
    }
    /**
     * Return true if this resolver produces case sensitive permissions.
     * @return true if this resolver produces case sensitive permissions.
     */
    public boolean isCaseSensitive() {
        return caseSensitive;
    }
    
    /**
     * Returns a new {@link WildcardPermission WildcardPermission} instance constructed based on the specified
     * <tt>permissionString</tt>.
     *
     * @param permissionString the permission string to convert to a {@link Permission Permission} instance.
     * @return a new {@link WildcardPermission WildcardPermission} instance constructed based on the specified
     *         <tt>permissionString</tt>
     */
    public Permission resolvePermission(String permissionString) {
        return new WildcardPermission(permissionString, caseSensitive);
    }
}
