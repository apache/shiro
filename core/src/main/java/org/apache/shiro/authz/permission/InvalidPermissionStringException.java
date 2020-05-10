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

import org.apache.shiro.lang.ShiroException;


/**
 * Thrown by {@link PermissionResolver#resolvePermission(String)} when the String being parsed is not
 * valid for that resolver.
 *
 * @since 0.9
 */
public class InvalidPermissionStringException extends ShiroException
{

    private String permissionString;

    /**
     * Constructs a new exception with the given message and permission string.
     *
     * @param message          the exception message.
     * @param permissionString the invalid permission string.
     */
    public InvalidPermissionStringException(String message, String permissionString) {
        super(message);
        this.permissionString = permissionString;
    }

    /**
     * Returns the permission string that was invalid and caused this exception to
     * be thrown.
     *
     * @return the permission string.
     */
    public String getPermissionString() {
        return this.permissionString;
    }


}
