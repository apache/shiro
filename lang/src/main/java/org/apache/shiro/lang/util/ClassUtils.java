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
package org.apache.shiro.lang.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;


/**
 * Utility method library used to conveniently interact with <code>Class</code>es, such as acquiring them from the
 * application <code>ClassLoader</code>s and instantiating Objects from them.
 *
 * @since 0.1
 */
public class ClassUtils {

    //TODO - complete JavaDoc

    /**
     * Private internal log instance.
     */
    private static final Logger log = LoggerFactory.getLogger(ClassUtils.class);


    /**
     * SHIRO-767: add a map to mapping primitive data type
     */
    private static final HashMap<String, Class<?>> primClasses
            = new HashMap<>(8, 1.0F);
    static {
        primClasses.put("boolean", boolean.class);
        primClasses.put("byte", byte.class);
        primClasses.put("char", char.class);
        primClasses.put("short", short.class);
        primClasses.put("int", int.class);
        primClasses.put("long", long.class);
        primClasses.put("float", float.class);
        primClasses.put("double", double.class);
        primClasses.put("void", void.class);
    }


    /**
     * @since 1.0
     */
    private static final ClassLoaderAccessor THREAD_CL_ACCESSOR = new ExceptionIgnoringAccessor() {
        @Override
        protected ClassLoader doGetClassLoader() throws Throwable {
            return Thread.currentThread().getContextClassLoader();
        }
    };

    /**
     * @since 1.0
     */
    private static final ClassLoaderAccessor CLASS_CL_ACCESSOR = new ExceptionIgnoringAccessor() {
        @Override
        protected ClassLoader doGetClassLoader() throws Throwable {
            return ClassUtils.class.getClassLoader();
        }
    };

    /**
     * @since 1.0
     */
    private static final ClassLoaderAccessor SYSTEM_CL_ACCESSOR = new ExceptionIgnoringAccessor() {
        @Override
        protected ClassLoader doGetClassLoader() throws Throwable {
            return ClassLoader.getSystemClassLoader();
        }
    };

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

        InputStream is = THREAD_CL_ACCESSOR.getResourceStream(name);

        if (is == null) {
            if (log.isTraceEnabled()) {
                log.trace("Resource [" + name + "] was not found via the thread context ClassLoader.  Trying the " +
                        "current ClassLoader...");
            }
            is = CLASS_CL_ACCESSOR.getResourceStream(name);
        }

        if (is == null) {
            if (log.isTraceEnabled()) {
                log.trace("Resource [" + name + "] was not found via the current class loader.  Trying the " +
                        "system/application ClassLoader...");
            }
            is = SYSTEM_CL_ACCESSOR.getResourceStream(name);
        }

        if (is == null && log.isTraceEnabled()) {
            log.trace("Resource [" + name + "] was not found via the thread context, current, or " +
                    "system/application ClassLoaders.  All heuristics have been exhausted.  Returning null.");
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

        Class clazz = THREAD_CL_ACCESSOR.loadClass(fqcn);

        if (clazz == null) {
            if (log.isTraceEnabled()) {
                log.trace("Unable to load class named [" + fqcn +
                        "] from the thread context ClassLoader.  Trying the current ClassLoader...");
            }
            clazz = CLASS_CL_ACCESSOR.loadClass(fqcn);
        }

        if (clazz == null) {
            if (log.isTraceEnabled()) {
                log.trace("Unable to load class named [" + fqcn + "] from the current ClassLoader.  " +
                        "Trying the system/application ClassLoader...");
            }
            clazz = SYSTEM_CL_ACCESSOR.loadClass(fqcn);
        }

        if (clazz == null) {
            //SHIRO-767: support for getting primitive data type,such as int,double...
            clazz = primClasses.get(fqcn);
        }

        if (clazz == null) {
            String msg = "Unable to load class named [" + fqcn + "] from the thread context, current, or " +
                    "system/application ClassLoaders.  All heuristics have been exhausted.  Class could not be found.";
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
            throw new InstantiationException("Unable to instantiate class [" + clazz.getName() + "]", e);
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
            throw new InstantiationException(msg, e);
        }
    }

    /**
     *
     * @param type
     * @param annotation
     * @return
     * @since 1.3
     */
    public static List<Method> getAnnotatedMethods(final Class<?> type, final Class<? extends Annotation> annotation) {
        final List<Method> methods = new ArrayList<Method>();
        Class<?> clazz = type;
        while (!Object.class.equals(clazz)) {
            Method[] currentClassMethods = clazz.getDeclaredMethods();
            for (final Method method : currentClassMethods) {
                if (annotation == null || method.isAnnotationPresent(annotation)) {
                    methods.add(method);
                }
            }
            // move to the upper class in the hierarchy in search for more methods
            clazz = clazz.getSuperclass();
        }
        return methods;
    }

    /**
     * @since 1.0
     */
    private static interface ClassLoaderAccessor {
        Class loadClass(String fqcn);
        InputStream getResourceStream(String name);
    }

    /**
     * @since 1.0
     */
    private static abstract class ExceptionIgnoringAccessor implements ClassLoaderAccessor {

        public Class loadClass(String fqcn) {
            Class clazz = null;
            ClassLoader cl = getClassLoader();
            if (cl != null) {
                try {
                    //SHIRO-767: Use Class.forName instead of cl.loadClass(), as byte arrays would fail otherwise.
                    clazz = Class.forName(fqcn, false, cl);
                } catch (ClassNotFoundException e) {
                    if (log.isTraceEnabled()) {
                        log.trace("Unable to load clazz named [" + fqcn + "] from class loader [" + cl + "]");
                    }
                }
            }
            return clazz;
        }

        public InputStream getResourceStream(String name) {
            InputStream is = null;
            ClassLoader cl = getClassLoader();
            if (cl != null) {
                is = cl.getResourceAsStream(name);
            }
            return is;
        }

        protected final ClassLoader getClassLoader() {
            try {
                return doGetClassLoader();
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Unable to acquire ClassLoader.", t);
                }
            }
            return null;
        }

        protected abstract ClassLoader doGetClassLoader() throws Throwable;
    }
}
