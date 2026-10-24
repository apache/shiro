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
package org.apache.shiro.aop;

import org.apache.shiro.aop.fixtures.SecuredInterfaceImpl;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.junit.jupiter.api.Test;

import java.lang.ref.WeakReference;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

import static org.assertj.core.api.Assertions.assertThat;

class AnnotationHierarchyClassLoaderTest {
    private static final int GC_ATTEMPTS = 50;
    private static final long GC_PAUSE_MILLIS = 100;

    /**
     * Defines its own copy of the classes in this package and delegates everything else.
     */
    private static final class IsolatedLoader extends URLClassLoader {
        IsolatedLoader(URL location, ClassLoader parent) {
            super(new URL[] {location}, parent);
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null && name.startsWith("org.apache.shiro.aop.AnnotationHierarchy")) {
                    loaded = findClass(name);
                }
                return loaded != null ? loaded : super.loadClass(name, resolve);
            }
        }
    }

    @Test
    void classFromAnotherLoaderDoesNotPinTheLoaderOfTheCache() throws Exception {
        WeakReference<ClassLoader> loader = inspectFromIsolatedLoader();
        for (int i = 0; i < GC_ATTEMPTS && loader.get() != null; i++) {
            System.gc();
            Thread.sleep(GC_PAUSE_MILLIS);
        }
        assertThat(loader.get()).as("loader of the second AnnotationHierarchy copy was reclaimed").isNull();
    }

    private static WeakReference<ClassLoader> inspectFromIsolatedLoader() throws Exception {
        URL location = AnnotationHierarchy.class.getProtectionDomain().getCodeSource().getLocation();
        IsolatedLoader loader = new IsolatedLoader(location, AnnotationHierarchyClassLoaderTest.class.getClassLoader());
        Class<?> isolated = loader.loadClass(AnnotationHierarchy.class.getName());
        assertThat(isolated.getClassLoader()).isSameAs(loader);
        Method adminOnly = SecuredInterfaceImpl.class.getMethod("adminOnly");
        Object found = isolated.getMethod("findAnnotation", Method.class, Class.class, Class.class)
                .invoke(null, adminOnly, SecuredInterfaceImpl.class, RequiresRoles.class);
        Object present = isolated.getMethod("isPresent", Class.class, Class.class)
                .invoke(null, SecuredInterfaceImpl.class, RequiresRoles.class);
        assertThat(found).isNotNull();
        assertThat(present).isEqualTo(true);
        return new WeakReference<>(loader);
    }
}
