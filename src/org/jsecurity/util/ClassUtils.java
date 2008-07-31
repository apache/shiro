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
package org.jsecurity.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.InputStream;
import java.lang.reflect.Constructor;

/**
 * @author Les Hazlewood
 * @since 0.1
 */
public class ClassUtils {

    private static final Log log = LogFactory.getLog(ClassUtils.class);

    /**
     * Returns the specified resource by checking the current thread's
     * {@link Thread#getContextClassLoader() context class loader}, then the
     * current ClassLoader (<code>ClassUtils.class.getClassLoader()</code>), then the system/application
     * ClassLoader (<code>ClassLoader.getSystemClassLoader()</code>, in that order, using
     * {@link ClassLoader#getResourceAsStream(String) getResourceAsStream(name)}.
     *
     * @param name the name of the resource to acquire from the classloader(s).
     * @return the InputStream of the resource found, or <code>null</code> if the resource cannot be found from any
     *         of the three mentioned ClassLoaders.
     * @since 0.9
     */
    public static InputStream getResourceAsStream(String name) {
        InputStream is = null;
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl != null) {
            is = cl.getResourceAsStream(name);
        }

        if (is == null) {
            if (log.isTraceEnabled()) {
                log.trace("Resource [" + name + "] was not found via the thread context ClassLoader.  Trying the " +
                        "current ClassLoader...");
            }
            cl = ClassUtils.class.getClassLoader();
            is = cl.getResourceAsStream(name);
            if (is == null) {
                if (log.isTraceEnabled()) {
                    log.trace("Resource [" + name + "] was not found via the current class loader.  Trying the " +
                            "system/application ClassLoader...");
                }
                cl = ClassLoader.getSystemClassLoader();
                is = cl.getResourceAsStream(name);
                if (is == null && log.isTraceEnabled()) {
                    log.trace("Resource [" + name + "] was not found via the thread context, current, or " +
                            "system/application ClassLoaders.  All heuristics have been exhausted.  Returning null.");
                }
            }
        }
        return is;
    }

    /**
     * Attempts to load the specified class name from the current thread's
     * {@link Thread#getContextClassLoader() context class loader}, then the
     * current ClassLoader (<code>ClassUtils.class.getClassLoader()</code>), then the system/application
     * ClassLoader (<code>ClassLoader.getSystemClassLoader()</code>, in that order.  If any of them cannot locate
     * the specified class, an <code>UnknownClassException</code> is thrown (our RuntimeException equivalent of
     * the JRE's <code>ClassNotFoundException</code>.
     *
     * @param fqcn the fully qualified class name to load
     * @return the located class
     * @throws UnknownClassException if the class cannot be found.
     */
    public static Class forName(String fqcn) throws UnknownClassException {
        Class clazz = null;
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl != null) {
            try {
                clazz = cl.loadClass(fqcn);
            } catch (ClassNotFoundException e) {
                if (log.isTraceEnabled()) {
                    log.trace("Unable to load class named [" + fqcn +
                            "] from the thread context ClassLoader.  Trying the current ClassLoader...");
                }
            }
        }
        if (clazz == null) {
            cl = ClassUtils.class.getClassLoader();
            try {
                clazz = cl.loadClass(fqcn);
            } catch (ClassNotFoundException e1) {
                if (log.isTraceEnabled()) {
                    log.trace("Unable to load class named [" + fqcn + "] from the current ClassLoader.  " +
                            "Trying the system/application ClassLoader...");
                }
                cl = ClassLoader.getSystemClassLoader();
                try {
                    clazz = cl.loadClass(fqcn);
                } catch (ClassNotFoundException ignored) {
                    if (log.isTraceEnabled()) {
                        log.trace("Unable to load class named [" + fqcn + "] from the " +
                                "system/application ClassLoader.");
                    }
                }
            }
        }

        if (clazz == null) {
            String msg = "Unable to load class named [" + fqcn + "] from the thread context, current, or " +
                    "system/application ClassLoaders.  All heuristics have been exausted.  Class could not be found.";
            throw new UnknownClassException(msg);
        }
        return clazz;
    }

    public static boolean isAvailable(String fullyQualifiedClassName) {
        try {
            forName(fullyQualifiedClassName);
            return true;
        } catch (UnknownClassException e) {
            return false;
        }
    }

    public static Object newInstance(String fqcn) {
        return newInstance(forName(fqcn));
    }

    public static Object newInstance(String fqcn, Object... args) {
        return newInstance(forName(fqcn), args);
    }

    public static Object newInstance(Class clazz) {
        if (clazz == null) {
            String msg = "Class method parameter cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        try {
            return clazz.newInstance();
        } catch (Exception e) {
            throw new org.jsecurity.util.InstantiationException("Unable to instantiate class [" + clazz.getName() + "]", e);
        }
    }

    public static Object newInstance(Class clazz, Object... args) {
        Class[] argTypes = new Class[args.length];
        for (int i = 0; i < args.length; i++) {
            argTypes[i] = args[i].getClass();
        }
        Constructor ctor = getConstructor(clazz, argTypes);
        return instantiate(ctor, args);
    }

    public static Constructor getConstructor(Class clazz, Class... argTypes) {
        try {
            return clazz.getConstructor(argTypes);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(e);
        }

    }

    public static Object instantiate(Constructor ctor, Object... args) {
        try {
            return ctor.newInstance(args);
        } catch (Exception e) {
            String msg = "Unable to instantiate Permission instance with constructor [" + ctor + "]";
            throw new org.jsecurity.util.InstantiationException(msg, e);
        }
    }


}
