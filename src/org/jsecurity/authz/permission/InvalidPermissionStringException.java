package org.jsecurity.authz.permission;

/**
 * Thrown by {@link PermissionResolver#resolvePermission(String)} when the String being parsed is not
 * valid for that resolver. 
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
