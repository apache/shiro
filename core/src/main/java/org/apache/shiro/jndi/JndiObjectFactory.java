package org.apache.shiro.jndi;

import org.apache.shiro.util.Factory;

import javax.naming.NamingException;

/**
 * A factory implementation intended to be used to look up objects in jndi.
 * @param <T>
 * @since 1.2
 */
public class JndiObjectFactory<T> extends JndiLocator implements Factory<T> {

    private String resourceName;
    private Class<? extends T> requiredType;

    public T getInstance() {
        try {
            if(requiredType != null) {
                return requiredType.cast(this.lookup(resourceName, requiredType));
            } else {
                return (T) this.lookup(resourceName);
            }
        } catch (NamingException e) {
            final String typeName = requiredType != null ? requiredType.getName() : "object";
            throw new IllegalStateException("Unable to look up " + typeName + " with jndi name '" + resourceName + "'.", e);
        }
    }

    public String getResourceName() {
        return resourceName;
    }

    public void setResourceName(String resourceName) {
        this.resourceName = resourceName;
    }

    public Class<? extends T> getRequiredType() {
        return requiredType;
    }

    public void setRequiredType(Class<? extends T> requiredType) {
        this.requiredType = requiredType;
    }
}
