package org.apache.shiro.env;

/**
 * An environment that supports object lookup by name.
 *
 * @since 1.2
 */
public interface NamedObjectEnvironment extends Environment {

    /**
     * Returns the object in Shiro's environment with the specified name and type or {@code null} if
     * no object with that name was found.
     *
     * @param name the assigned name of the object.
     * @param requiredType the class that the discovered object should be.  If the object is not the specified type, a
     * @param <T> the type of the class
     * @throws RequiredTypeException if the discovered object does not equal, extend, or implement the specified class.
     * @return the object in Shiro's environment with the specified name (of the specified type) or {@code null} if
     * no object with that name was found.
     */
    <T> T getObject(String name, Class<T> requiredType) throws RequiredTypeException;
}
