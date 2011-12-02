package org.apache.shiro.env;

/**
 * Exception thrown when attempting to acquire an object of a required type and that object does not equal, extend, or
 * implement a specified {@code Class}.
 *
 * @since 1.2
 */
public class RequiredTypeException extends EnvironmentException {

    public RequiredTypeException(String message) {
        super(message);
    }

    public RequiredTypeException(String message, Throwable cause) {
        super(message, cause);
    }
}
