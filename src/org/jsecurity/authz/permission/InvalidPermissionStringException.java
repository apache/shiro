/*
 * Copyright 2005-2008 Jeremy Haile
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
package org.jsecurity.authz.permission;

/**
 * Thrown by {@link PermissionResolver#resolvePermission(String)} when the String being parsed is not
 * valid for that resolver.
 * @author Jeremy Haile
 * @since 0.9 
 */
public class InvalidPermissionStringException extends RuntimeException {

    private String permissionString;

    /**
     * Constructs a new exception with the given message and permission string.
     * @param message the exception message.
     * @param permissionString the invalid permission string.
     */
    public InvalidPermissionStringException(String message, String permissionString) {
        super(message);
        this.permissionString = permissionString;
    }

    /**
     * Returns the permission string that was invalid and caused this exception to
     * be thrown.
     * @return the permission string.
     */
    public String getPermissionString() {
        return this.permissionString;
    }


}
