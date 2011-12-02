package org.apache.shiro.env;

import org.apache.shiro.ShiroException;

/**
 * Exception thrown for errors related to {@link Environment} instances or configuration.
 *
 * @since 1.2
 */
public class EnvironmentException extends ShiroException {

    public EnvironmentException(String message) {
        super(message);
    }

    public EnvironmentException(String message, Throwable cause) {
        super(message, cause);
    }
}
