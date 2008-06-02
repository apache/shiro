/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.util;

import java.io.InputStream;
import java.lang.reflect.Constructor;

/**
 * @since 0.1
 * @author Les Hazlewood
 */
public class ClassUtils {

    public static ClassLoader getDefaultClassLoader() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if ( cl == null ) {
            cl = ClassUtils.class.getClassLoader();
        }
        return cl;
    }

    /**
     *
     * @param name
     * @return
     * @since 0.9
     */
    public static InputStream getResourceAsStream( String name ) {
        ClassLoader cl = getDefaultClassLoader();
        return cl.getResourceAsStream(name);
    }

    public static Class forName( String fullyQualified ) throws UnknownClassException {
        ClassLoader cl = getDefaultClassLoader();
        try {
            return cl.loadClass( fullyQualified );
        } catch ( ClassNotFoundException e ) {
            String msg = "Unable to load class name [" + fullyQualified + "] from ClassLoader [" +
                cl + "]";
            throw new UnknownClassException( msg, e );
        }
    }

    public static boolean isAvailable( String fullyQualifiedClassName ) {
        try {
            forName( fullyQualifiedClassName );
            return true;
        } catch (UnknownClassException e) {
            return false;
        }
    }

    public static Object newInstance( String fqcn ) {
        return newInstance( forName( fqcn ) );
    }

    public static Object newInstance( String fqcn, Object... args ) {
        return newInstance( forName(fqcn), args );
    }

    public static Object newInstance( Class clazz ) {
        if ( clazz == null ) {
            String msg = "Class method parameter cannot be null.";
            throw new IllegalArgumentException( msg );
        }
        try {
            return clazz.newInstance();
        } catch ( Exception e ) {
            throw new org.jsecurity.util.InstantiationException( "Unable to instantiate class [" + clazz.getName() + "]", e );
        }
    }

    public static Object newInstance( Class clazz, Object... args ) {
        Class[] argTypes = new Class[args.length];
        for( int i = 0; i < args.length; i++ ) {
            argTypes[i] = args[i].getClass();
        }
        Constructor ctor = getConstructor(clazz,argTypes);
        return instantiate(ctor, args);
    }

    public static Constructor getConstructor( Class clazz, Class... argTypes ) {
        try {
            return clazz.getConstructor(argTypes);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(e);
        }

    }

    public static Object instantiate( Constructor ctor, Object... args ) {
        try {
            return ctor.newInstance( args );
        } catch ( Exception e ) {
            String msg = "Unable to instantiate Permission instance with constructor [" + ctor + "]";
            throw new org.jsecurity.util.InstantiationException( msg, e );
        }
    }


}
