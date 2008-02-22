/*
 * Copyright (C) 2005-2008 Jeremy Haile
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.authz.permission;

/**
 * Thrown by {@link PermissionResolver#resolvePermission(String)} when the String being parsed is not
 * valid for that resolver.
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
