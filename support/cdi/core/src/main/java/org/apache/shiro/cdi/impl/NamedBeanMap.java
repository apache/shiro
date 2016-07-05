/*
 * Copyright 2013 Harald Wellmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shiro.cdi.impl;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Partial immutable {@link Map} implementation to provide a subset of CDI beans as Shiro beans to be
 * referenced in INI files. The keys are bean names, the values are bean instances.
 * <p>
 * To be considered, a CDI bean must be qualified with {@link ShiroIni} and optionally with
 * {@code @Named}. 
 * <p>
 * Contextual references of these beans are eagerly created when this class is instantiated. This
 * is the main reason for using the dedicated {@code ShiroIni} qualifier, to avoid instantiating
 * <em>all</em> named beans.
 */
public class NamedBeanMap implements Map<String, Object> {

    private static Logger log = LoggerFactory.getLogger(NamedBeanMap.class);

    private Map<String, Object> beans = new HashMap<String, Object>();

    /**
     * 
     */
    public NamedBeanMap(BeanManager beanManager) {
        for (Bean<?> bean : beanManager.getBeans(Object.class, ShiroIniLiteral.INSTANCE)) {
            String beanName = getShiroBeanName(bean);
            if (beanName == null) {
                log.warn("Shiro cannot derive a default name for [{}], "
                    + "so this bean cannot be referenced in shiro.ini. "
                    + "Consider adding a @Named qualifier.", bean);
            }
            else {
                log.debug("Found @ShiroIni bean with name [{}]", beanName);
                CreationalContext<Object> cc = beanManager.createCreationalContext(null);
                Object object = beanManager.getReference(bean, Object.class, cc);
                beans.put(beanName, object);
            }
        }
    }

    /**
     * @param bean
     * @return
     */
    private String getShiroBeanName(Bean<?> bean) {
        String beanName = bean.getName();
        if (beanName == null) {
            if (bean.getTypes().contains(bean.getBeanClass())) {
                String className = bean.getBeanClass().getSimpleName();
                char first = Character.toLowerCase(className.charAt(0));
                beanName = first + className.substring(1);
            }
        }
        return beanName;
    }

    public int size() {
        return beans.size();
    }

    public boolean isEmpty() {
        return beans.isEmpty();
    }

    public boolean containsKey(Object key) {
        return beans.containsKey(key);
    }

    public boolean containsValue(Object value) {
        throw new UnsupportedOperationException();
    }

    public Object get(Object key) {
        return beans.get(key);
    }

    public Object put(String key, Object value) {
        throw new UnsupportedOperationException();
    }

    public Object remove(Object key) {
        throw new UnsupportedOperationException();
    }

    public void putAll(Map<? extends String, ? extends Object> m) {
        throw new UnsupportedOperationException();
    }

    public void clear() {
        throw new UnsupportedOperationException();
    }

    public Set<String> keySet() {
        return beans.keySet();
    }

    public Collection<Object> values() {
        return beans.values();
    }

    public Set<java.util.Map.Entry<String, Object>> entrySet() {
        return beans.entrySet();
    }
}
