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
package org.apache.shiro.guice;

import com.google.common.primitives.Primitives;
import com.google.inject.*;
import com.google.inject.matcher.Matcher;
import com.google.inject.matcher.Matchers;
import com.google.inject.name.Names;
import com.google.inject.spi.TypeEncounter;
import com.google.inject.spi.TypeListener;
import org.apache.commons.beanutils.PropertyUtils;
import org.apache.shiro.SecurityUtils;

import java.beans.PropertyDescriptor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

/**
 * TypeListener that injects setter methods on Shiro objects.
 */
class BeanTypeListener implements TypeListener {
    public static final Package SHIRO_GUICE_PACKAGE = ShiroModule.class.getPackage();
    public static final Package SHIRO_PACKAGE = SecurityUtils.class.getPackage();

    private static Matcher<Class> shiroMatcher = Matchers.inSubpackage(SHIRO_PACKAGE.getName());
    private static Matcher<Class> shiroGuiceMatcher = Matchers.inSubpackage(SHIRO_GUICE_PACKAGE.getName());

    private static Matcher<Class> classMatcher = ShiroMatchers.ANY_PACKAGE.and(shiroMatcher.and(Matchers.not(shiroGuiceMatcher)));

    public static final Matcher<TypeLiteral> MATCHER = ShiroMatchers.typeLiteral(classMatcher);

    public <I> void hear(TypeLiteral<I> type, final TypeEncounter<I> encounter) {
        PropertyDescriptor propertyDescriptors[] = PropertyUtils.getPropertyDescriptors(type.getRawType());
        final Map<PropertyDescriptor, Key<?>> propertyDependencies = new HashMap<PropertyDescriptor, Key<?>>(propertyDescriptors.length);
        final Provider<Injector> injectorProvider = encounter.getProvider(Injector.class);
        for (PropertyDescriptor propertyDescriptor : propertyDescriptors) {
            if (propertyDescriptor.getWriteMethod() != null && Modifier.isPublic(propertyDescriptor.getWriteMethod().getModifiers())) {
                Type propertyType = propertyDescriptor.getWriteMethod().getGenericParameterTypes()[0];
                propertyDependencies.put(propertyDescriptor, requiresName(propertyType)
                        ? Key.get(propertyType, Names.named("shiro." + propertyDescriptor.getName()))
                        : Key.get(propertyType));
            }
        }
        encounter.register(new MembersInjector<I>() {
            public void injectMembers(I instance) {
                for (Map.Entry<PropertyDescriptor, Key<?>> dependency : propertyDependencies.entrySet()) {
                    try {
                        Object value = injectorProvider.get().getInstance(dependency.getValue());
                        dependency.getKey().getWriteMethod().invoke(instance, value);

                    } catch (ConfigurationException e) {
                        // This is ok, it simply means that we can't fulfill this dependency.
                        // Is there a better way to do this?
                    } catch (InvocationTargetException e) {
                        throw new RuntimeException("Couldn't set property " + dependency.getKey().getDisplayName(), e);
                    } catch (IllegalAccessException e) {
                        throw new RuntimeException("We shouldn't have ever reached this point, we don't try to inject to non-accessible methods.", e);
                    }
                }

            }
        });
    }

    private static boolean requiresName(Type propertyType) {
        if (propertyType instanceof Class) {
            Class<?> aClass = (Class<?>) propertyType;
            return aClass.isPrimitive() || aClass.isEnum() || Primitives.isWrapperType(aClass) || CharSequence.class.isAssignableFrom(aClass);
        } else {
            return false;
        }
    }
}
