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
package org.apache.shiro.env;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.lang.util.Destroyable;
import org.apache.shiro.lang.util.LifecycleUtils;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple/default {@code Environment} implementation that stores Shiro objects as key-value pairs in a
 * {@link java.util.Map Map} instance.  The key is the object name, the value is the object itself.
 *
 * @since 1.2
 */
public class DefaultEnvironment implements NamedObjectEnvironment, Destroyable {

    /**
     * The default name under which the application's {@code SecurityManager} instance may be acquired, equal to
     * {@code securityManager}.
     */
    public static final String DEFAULT_SECURITY_MANAGER_KEY = "securityManager";

    protected final Map<String, Object> objects;
    private String securityManagerName;

    /**
     * Creates a new instance with a thread-safe {@link ConcurrentHashMap} backing map.
     */
    public DefaultEnvironment() {
        this(new ConcurrentHashMap<String, Object>());
    }

    /**
     * Creates a new instance with the specified backing map.
     *
     * @param seed backing map to use to maintain Shiro objects.
     */
    @SuppressWarnings({"unchecked"})
    public DefaultEnvironment(Map<String, ?> seed) {
        this.securityManagerName = DEFAULT_SECURITY_MANAGER_KEY;
        if (seed == null) {
            throw new IllegalArgumentException("Backing map cannot be null.");
        }
        this.objects = (Map<String, Object>) seed;
    }

    /**
     * Returns the application's {@code SecurityManager} instance accessible in the backing map using the
     * {@link #getSecurityManagerName() securityManagerName} property as the lookup key.
     * <p/>
     * This implementation guarantees that a non-null instance is always returned, as this is expected for
     * Environment API end-users.  If subclasses have the need to perform the map lookup without this guarantee
     * (for example, during initialization when the instance may not have been added to the map yet), the
     * {@link #lookupSecurityManager()} method is provided as an alternative.
     *
     * @return the application's {@code SecurityManager} instance accessible in the backing map using the
     *         {@link #getSecurityManagerName() securityManagerName} property as the lookup key.
     */
    public SecurityManager getSecurityManager() throws IllegalStateException {
        SecurityManager securityManager = lookupSecurityManager();
        if (securityManager == null) {
            throw new IllegalStateException("No SecurityManager found in Environment.  This is an invalid " +
                    "environment state.");
        }
        return securityManager;
    }

    public void setSecurityManager(SecurityManager securityManager) {
        if (securityManager == null) {
            throw new IllegalArgumentException("Null SecurityManager instances are not allowed.");
        }
        String name = getSecurityManagerName();
        setObject(name, securityManager);
    }

    /**
     * Looks up the {@code SecurityManager} instance in the backing map without performing any non-null guarantees.
     *
     * @return the {@code SecurityManager} in the backing map, or {@code null} if it has not yet been populated.
     */
    protected SecurityManager lookupSecurityManager() {
        String name = getSecurityManagerName();
        return getObject(name, SecurityManager.class);
    }

    /**
     * Returns the name of the {@link SecurityManager} instance in the backing map.  Used as a key to lookup the
     * instance.  Unless set otherwise, the default is {@code securityManager}.
     *
     * @return the name of the {@link SecurityManager} instance in the backing map.  Used as a key to lookup the
     *         instance.
     */
    public String getSecurityManagerName() {
        return securityManagerName;
    }

    /**
     * Sets the name of the {@link SecurityManager} instance in the backing map.  Used as a key to lookup the
     * instance.  Unless set otherwise, the default is {@code securityManager}.
     *
     * @param securityManagerName the name of the {@link SecurityManager} instance in the backing map.  Used as a key
     *                            to lookup the instance. 
     */
    public void setSecurityManagerName(String securityManagerName) {
        this.securityManagerName = securityManagerName;
    }

    /**
     * Returns the live (modifiable) internal objects collection.
     *
     * @return the live (modifiable) internal objects collection.
     */
    public Map<String,Object> getObjects() {
        return this.objects;
    }

    @SuppressWarnings({"unchecked"})
    public <T> T getObject(String name, Class<T> requiredType) throws RequiredTypeException {
        if (name == null) {
            throw new NullPointerException("name parameter cannot be null.");
        }
        if (requiredType == null) {
            throw new NullPointerException("requiredType parameter cannot be null.");
        }
        Object o = this.objects.get(name);
        if (o == null) {
            return null;
        }
        if (!requiredType.isInstance(o)) {
            String msg = "Object named '" + name + "' (of type [" + o.getClass().getName() + "]) is not of required type [" + requiredType.getName() + "].";
            throw new RequiredTypeException(msg);
        }
        return (T)o;
    }

    public void setObject(String name, Object instance) {
        if (name == null) {
            throw new NullPointerException("name parameter cannot be null.");
        }
        if (instance == null) {
            this.objects.remove(name);
        } else {
            this.objects.put(name, instance);
        }
    }


    public void destroy() throws Exception {
        LifecycleUtils.destroy(this.objects.values());
    }
}
