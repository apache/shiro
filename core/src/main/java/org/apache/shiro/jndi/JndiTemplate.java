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
package org.apache.shiro.jndi;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Properties;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helper class that simplifies JNDI operations. It provides methods to lookup and
 * bind objects, and allows implementations of the {@link JndiCallback} interface
 * to perform any operation they like with a JNDI naming context provided.
 * <p/>
 * <p>Note that this implementation is an almost exact copy of the Spring Framework's identically named class from
 * their 2.5.4 distribution - we didn't want to re-invent the wheel, but not require a full dependency on the
 * Spring framework, nor does Spring make available only its JNDI classes in a small jar, or we would have used that.
 * Since Shiro is also Apache 2.0 licensed, all regular licenses and conditions and authors have remained in tact.
 *
 * @see JndiCallback
 * @see #execute
 */
public class JndiTemplate {

    private static final Logger log = LoggerFactory.getLogger(JndiTemplate.class);

    private Properties environment;

    /** Create a new JndiTemplate instance. */
    public JndiTemplate() {
    }

    /**
     * Create a new JndiTemplate instance, using the given environment.
     *
     * @param environment the Properties to initialize with
     */
    public JndiTemplate(Properties environment) {
        this.environment = environment;
    }

    /**
     * Set the environment for the JNDI InitialContext.
     *
     * @param environment the Properties to initialize with
     */
    public void setEnvironment(Properties environment) {
        this.environment = environment;
    }

    /**
     * Return the environment for the JNDI InitialContext, or <code>null</code> if none should be used.
     *
     * @return the environment for the JNDI InitialContext, or <code>null</code> if none should be used.
     */
    public Properties getEnvironment() {
        return this.environment;
    }

    /**
     * Execute the given JNDI context callback implementation.
     *
     * @param contextCallback JndiCallback implementation
     * @return a result object returned by the callback, or <code>null</code>
     * @throws NamingException thrown by the callback implementation
     * @see #createInitialContext
     */
    public Object execute(JndiCallback contextCallback) throws NamingException {
        Context ctx = createInitialContext();
        try {
            return contextCallback.doInContext(ctx);
        }
        finally {
            try {
                ctx.close();
            } catch (NamingException ex) {
                log.debug("Could not close JNDI InitialContext", ex);
            }
        }
    }

    /**
     * Create a new JNDI initial context. Invoked by {@link #execute}.
     * <p>The default implementation use this template's environment settings.
     * Can be subclassed for custom contexts, e.g. for testing.
     *
     * @return the initial Context instance
     * @throws NamingException in case of initialization errors
     */
    @SuppressWarnings({"unchecked"})
    protected Context createInitialContext() throws NamingException {
        Properties env = getEnvironment();
        Hashtable icEnv = null;
        if (env != null) {
            icEnv = new Hashtable(env.size());
            for (Enumeration en = env.propertyNames(); en.hasMoreElements();) {
                String key = (String) en.nextElement();
                icEnv.put(key, env.getProperty(key));
            }
        }
        return new InitialContext(icEnv);
    }

    /**
     * Look up the object with the given name in the current JNDI context.
     *
     * @param name the JNDI name of the object
     * @return object found (cannot be <code>null</code>; if a not so well-behaved
     *         JNDI implementations returns null, a NamingException gets thrown)
     * @throws NamingException if there is no object with the given
     *                         name bound to JNDI
     */
    public Object lookup(final String name) throws NamingException {
        log.debug("Looking up JNDI object with name '{}'", name);
        return execute(new JndiCallback() {
            public Object doInContext(Context ctx) throws NamingException {
                Object located = ctx.lookup(name);
                if (located == null) {
                    throw new NameNotFoundException(
                            "JNDI object with [" + name + "] not found: JNDI implementation returned null");
                }
                return located;
            }
        });
    }

    /**
     * Look up the object with the given name in the current JNDI context.
     *
     * @param name         the JNDI name of the object
     * @param requiredType type the JNDI object must match. Can be an interface or
     *                     superclass of the actual class, or <code>null</code> for any match. For example,
     *                     if the value is <code>Object.class</code>, this method will succeed whatever
     *                     the class of the returned instance.
     * @return object found (cannot be <code>null</code>; if a not so well-behaved
     *         JNDI implementations returns null, a NamingException gets thrown)
     * @throws NamingException if there is no object with the given
     *                         name bound to JNDI
     */
    public Object lookup(String name, Class requiredType) throws NamingException {
        Object jndiObject = lookup(name);
        if (requiredType != null && !requiredType.isInstance(jndiObject)) {
            String msg = "Jndi object acquired under name '" + name + "' is of type [" +
                    jndiObject.getClass().getName() + "] and not assignable to the required type [" +
                    requiredType.getName() + "].";
            throw new NamingException(msg);
        }
        return jndiObject;
    }

    /**
     * Bind the given object to the current JNDI context, using the given name.
     *
     * @param name   the JNDI name of the object
     * @param object the object to bind
     * @throws NamingException thrown by JNDI, mostly name already bound
     */
    public void bind(final String name, final Object object) throws NamingException {
        log.debug("Binding JNDI object with name '{}'", name);
        execute(new JndiCallback() {
            public Object doInContext(Context ctx) throws NamingException {
                ctx.bind(name, object);
                return null;
            }
        });
    }

    /**
     * Rebind the given object to the current JNDI context, using the given name.
     * Overwrites any existing binding.
     *
     * @param name   the JNDI name of the object
     * @param object the object to rebind
     * @throws NamingException thrown by JNDI
     */
    public void rebind(final String name, final Object object) throws NamingException {
        log.debug("Rebinding JNDI object with name '{}'", name);
        execute(new JndiCallback() {
            public Object doInContext(Context ctx) throws NamingException {
                ctx.rebind(name, object);
                return null;
            }
        });
    }

    /**
     * Remove the binding for the given name from the current JNDI context.
     *
     * @param name the JNDI name of the object
     * @throws NamingException thrown by JNDI, mostly name not found
     */
    public void unbind(final String name) throws NamingException {
        log.debug("Unbinding JNDI object with name '{}'", name);
        execute(new JndiCallback() {
            public Object doInContext(Context ctx) throws NamingException {
                ctx.unbind(name);
                return null;
            }
        });
    }

}
