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

import com.google.inject.Binder;
import com.google.inject.ConfigurationException;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.MembersInjector;
import com.google.inject.Provider;
import com.google.inject.TypeLiteral;
import com.google.inject.matcher.Matcher;
import com.google.inject.matcher.Matchers;
import com.google.inject.multibindings.MapBinder;
import com.google.inject.name.Names;
import com.google.inject.spi.TypeEncounter;
import com.google.inject.spi.TypeListener;
import com.google.inject.util.Types;
import org.apache.commons.beanutils.BeanUtilsBean;
import org.apache.commons.beanutils.SuppressPropertiesBeanIntrospector;
import org.apache.shiro.SecurityUtils;

import java.beans.PropertyDescriptor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * TypeListener that injects setter methods on Shiro objects.
 */
class BeanTypeListener implements TypeListener {
    public static final Package SHIRO_GUICE_PACKAGE = ShiroModule.class.getPackage();
    public static final Package SHIRO_PACKAGE = SecurityUtils.class.getPackage();


    /**
     * @since 1.4
     */
    public static final String BEAN_TYPE_MAP_NAME = "__SHIRO_BEAN_TYPES__";

    static final Key<?> MAP_KEY = Key.get(Types.mapOf(TypeLiteral.class, BeanTypeKey.class), Names.named(BEAN_TYPE_MAP_NAME));

    static Matcher<Class> shiroMatcher = Matchers.inSubpackage(SHIRO_PACKAGE.getName());
    static Matcher<Class> shiroGuiceMatcher = Matchers.inSubpackage(SHIRO_GUICE_PACKAGE.getName());
    static Matcher<Class> classMatcher = ShiroMatchers.anyPackage.and(shiroMatcher.and(Matchers.not(shiroGuiceMatcher)));

    static final Matcher<TypeLiteral> MATCHER = ShiroMatchers.typeLiteral(classMatcher);

    private static final Set<Class<?>> WRAPPER_TYPES = new HashSet<Class<?>>(Arrays.asList(
            Byte.class,
            Boolean.class,
            Character.class,
            Double.class,
            Float.class,
            Integer.class,
            Long.class,
            Short.class,
            Void.class));

    private final BeanUtilsBean beanUtilsBean;

    BeanTypeListener() {
        // SHIRO-619
        beanUtilsBean = new BeanUtilsBean();
        beanUtilsBean.getPropertyUtils().addBeanIntrospector(
                SuppressPropertiesBeanIntrospector.SUPPRESS_CLASS);
    }

    @SuppressWarnings("checkstyle:LineLength")
    public <I> void hear(TypeLiteral<I> type, final TypeEncounter<I> encounter) {
        PropertyDescriptor[] propertyDescriptors = beanUtilsBean.getPropertyUtils().getPropertyDescriptors(type.getRawType());
        final Map<PropertyDescriptor, Key<?>> propertyDependencies = new HashMap<PropertyDescriptor, Key<?>>(propertyDescriptors.length);
        final Provider<Injector> injectorProvider = encounter.getProvider(Injector.class);
        for (PropertyDescriptor propertyDescriptor : propertyDescriptors) {
            if (propertyDescriptor.getWriteMethod() != null && Modifier.isPublic(propertyDescriptor.getWriteMethod().getModifiers())) {
                Type propertyType = propertyDescriptor.getWriteMethod().getGenericParameterTypes()[0];
                propertyDependencies.put(propertyDescriptor, createDependencyKey(propertyDescriptor, propertyType));
            }
        }
        encounter.register(new MembersInjector<I>() {
            public void injectMembers(I instance) {
                for (Map.Entry<PropertyDescriptor, Key<?>> dependency : propertyDependencies.entrySet()) {
                    try {
                        final Injector injector = injectorProvider.get();

                        Object value = injector.getInstance(getMappedKey(injector, dependency.getValue()));
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

    private static Key<?> getMappedKey(Injector injector, Key<?> key) {
        Map<TypeLiteral, BeanTypeKey> beanTypeMap = getBeanTypeMap(injector);
        if (key.getAnnotation() == null && beanTypeMap.containsKey(key.getTypeLiteral())) {
            return beanTypeMap.get(key.getTypeLiteral()).key;
        } else {
            return key;
        }
    }

    @SuppressWarnings({"unchecked"})
    private static Map<TypeLiteral, BeanTypeKey> getBeanTypeMap(Injector injector) {
        return (Map<TypeLiteral, BeanTypeKey>) injector.getInstance(MAP_KEY);
    }

    private static Key<?> createDependencyKey(PropertyDescriptor propertyDescriptor, Type propertyType) {
        if (requiresName(propertyType)) {
            return Key.get(propertyType, Names.named("shiro." + propertyDescriptor.getName()));
        } else {
            return Key.get(propertyType);
        }
    }

    @SuppressWarnings("checkstyle:LineLength")
    private static boolean requiresName(Type propertyType) {
        if (propertyType instanceof Class) {
            Class<?> aClass = (Class<?>) propertyType;
            return aClass.isPrimitive() || aClass.isEnum() || WRAPPER_TYPES.contains(aClass) || CharSequence.class.isAssignableFrom(aClass);
        } else {
            return false;
        }
    }

    static void ensureBeanTypeMapExists(Binder binder) {
        beanTypeMapBinding(binder).addBinding(TypeLiteral.get(BeanTypeKey.class)).toInstance(new BeanTypeKey(null));
    }

    static <T> void bindBeanType(Binder binder, TypeLiteral<T> typeLiteral, Key<? extends T> key) {
        beanTypeMapBinding(binder).addBinding(typeLiteral).toInstance(new BeanTypeKey(key));
    }

    private static MapBinder<TypeLiteral, BeanTypeKey> beanTypeMapBinding(Binder binder) {
        return MapBinder.newMapBinder(binder, TypeLiteral.class, BeanTypeKey.class, Names.named(BEAN_TYPE_MAP_NAME));
    }

    private static final class BeanTypeKey {
        Key<?> key;

        private BeanTypeKey(Key<?> key) {
            this.key = key;
        }
    }
}
