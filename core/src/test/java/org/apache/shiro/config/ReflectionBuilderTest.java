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
package org.apache.shiro.config;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.jndi.JndiObjectFactory;
import org.apache.shiro.util.CollectionUtils;
import org.junit.Test;

import java.util.*;

import static org.junit.Assert.*;

/**
 * @since Aug 5, 2008 9:53:00 AM
 */
public class ReflectionBuilderTest {

    @Test
    public void testSimpleConfig() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("compositeBean", "org.apache.shiro.config.CompositeBean");
        defs.put("compositeBean.stringProp", "blah");
        defs.put("compositeBean.booleanProp", "true");
        defs.put("compositeBean.intProp", "42");

        ReflectionBuilder builder = new ReflectionBuilder();
        Map beans = builder.buildObjects(defs);

        CompositeBean compositeBean = (CompositeBean) beans.get("compositeBean");
        assertNotNull(compositeBean);
        assertEquals(compositeBean.getStringProp(), "blah");
        assertTrue(compositeBean.isBooleanProp());
        assertEquals(compositeBean.getIntProp(), 42);
    }

    @Test
    public void testSimpleConfigWithDollarSignStringValue() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("compositeBean", "org.apache.shiro.config.CompositeBean");
        defs.put("compositeBean.stringProp", "\\$500");

        ReflectionBuilder builder = new ReflectionBuilder();
        Map beans = builder.buildObjects(defs);

        CompositeBean compositeBean = (CompositeBean) beans.get("compositeBean");
        assertEquals(compositeBean.getStringProp(), "$500");
    }

    @Test
    public void testObjectReferenceConfig() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean", "org.apache.shiro.config.SimpleBean");
        defs.put("simpleBean.intProp", "101");
        defs.put("compositeBean", "org.apache.shiro.config.CompositeBean");
        defs.put("compositeBean.stringProp", "blah");
        defs.put("compositeBean.simpleBean", "$simpleBean");

        ReflectionBuilder builder = new ReflectionBuilder();
        Map beans = builder.buildObjects(defs);

        CompositeBean compositeBean = (CompositeBean) beans.get("compositeBean");
        assertNotNull(compositeBean);
        assertEquals(compositeBean.getStringProp(), "blah");
        SimpleBean simpleBean = (SimpleBean) beans.get("simpleBean");
        assertNotNull(simpleBean);
        assertNotNull(compositeBean.getSimpleBean());
        assertEquals(simpleBean, compositeBean.getSimpleBean());
        assertEquals(simpleBean.getIntProp(), 101);
    }

    @Test(expected = ConfigurationException.class)
    public void testObjectReferenceConfigWithTypeMismatch() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean", "org.apache.shiro.config.SimpleBean");
        defs.put("compositeBean", "org.apache.shiro.config.CompositeBean");
        defs.put("compositeBean.simpleBean", "simpleBean");
        ReflectionBuilder builder = new ReflectionBuilder();
        builder.buildObjects(defs);
    }

    @Test(expected = UnresolveableReferenceException.class)
    public void testObjectReferenceConfigWithInvalidReference() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean", "org.apache.shiro.config.SimpleBean");
        defs.put("compositeBean", "org.apache.shiro.config.CompositeBean");
        defs.put("compositeBean.simpleBean", "$foo");
        ReflectionBuilder builder = new ReflectionBuilder();
        builder.buildObjects(defs);
    }

    @Test
    public void testSetProperty() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean1", "org.apache.shiro.config.SimpleBean");
        defs.put("simpleBean2", "org.apache.shiro.config.SimpleBean");
        defs.put("compositeBean", "org.apache.shiro.config.CompositeBean");
        defs.put("compositeBean.simpleBeanSet", "$simpleBean1, $simpleBean2, $simpleBean2");
        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertFalse(CollectionUtils.isEmpty(objects));
        CompositeBean cBean = (CompositeBean) objects.get("compositeBean");
        assertNotNull(cBean);
        Set<SimpleBean> simpleBeans = cBean.getSimpleBeanSet();
        assertNotNull(simpleBeans);
        assertEquals(2, simpleBeans.size());
    }

    @Test
    public void testListProperty() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean1", "org.apache.shiro.config.SimpleBean");
        defs.put("simpleBean2", "org.apache.shiro.config.SimpleBean");
        defs.put("compositeBean", "org.apache.shiro.config.CompositeBean");
        defs.put("compositeBean.simpleBeanList", "$simpleBean1, $simpleBean2, $simpleBean2");
        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertFalse(CollectionUtils.isEmpty(objects));
        CompositeBean cBean = (CompositeBean) objects.get("compositeBean");
        assertNotNull(cBean);
        List<SimpleBean> simpleBeans = cBean.getSimpleBeanList();
        assertNotNull(simpleBeans);
        assertEquals(3, simpleBeans.size());
    }

    @Test
    public void testCollectionProperty() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean1", "org.apache.shiro.config.SimpleBean");
        defs.put("simpleBean2", "org.apache.shiro.config.SimpleBean");
        defs.put("compositeBean", "org.apache.shiro.config.CompositeBean");
        defs.put("compositeBean.simpleBeanCollection", "$simpleBean1, $simpleBean2, $simpleBean2");
        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertFalse(CollectionUtils.isEmpty(objects));
        CompositeBean cBean = (CompositeBean) objects.get("compositeBean");
        assertNotNull(cBean);
        Collection<SimpleBean> simpleBeans = cBean.getSimpleBeanCollection();
        assertNotNull(simpleBeans);
        assertTrue(simpleBeans instanceof List);
        assertEquals(3, simpleBeans.size());
    }

    @Test
    public void testByteArrayHexProperty() {
        String source = "Hello, world.";
        byte[] bytes = CodecSupport.toBytes(source);
        String hex = Hex.encodeToString(bytes);
        String hexValue = "0x" + hex;

        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean", "org.apache.shiro.config.SimpleBean");
        defs.put("simpleBean.byteArrayProp", hexValue);
        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertFalse(CollectionUtils.isEmpty(objects));
        SimpleBean bean = (SimpleBean) objects.get("simpleBean");
        assertNotNull(bean);
        byte[] beanBytes = bean.getByteArrayProp();
        assertNotNull(beanBytes);
        String reconstituted = CodecSupport.toString(beanBytes);
        assertEquals(source, reconstituted);
    }

    @Test
    public void testByteArrayBase64Property() {
        String source = "Hello, world.";
        byte[] bytes = CodecSupport.toBytes(source);
        String base64 = Base64.encodeToString(bytes);

        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean", "org.apache.shiro.config.SimpleBean");
        defs.put("simpleBean.byteArrayProp", base64);
        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        SimpleBean bean = (SimpleBean) objects.get("simpleBean");
        byte[] beanBytes = bean.getByteArrayProp();
        assertNotNull(beanBytes);
        assertTrue(Arrays.equals(beanBytes, bytes));
        String reconstituted = CodecSupport.toString(beanBytes);
        assertEquals(reconstituted, source);
    }

    @Test
    public void testMapProperty() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean1", "org.apache.shiro.config.SimpleBean");
        defs.put("simpleBean2", "org.apache.shiro.config.SimpleBean");
        defs.put("compositeBean", "org.apache.shiro.config.CompositeBean");
        defs.put("compositeBean.simpleBeanMap", "simpleBean1:$simpleBean1, simpleBean2:$simpleBean2");
        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertFalse(CollectionUtils.isEmpty(objects));
        CompositeBean cBean = (CompositeBean) objects.get("compositeBean");
        assertNotNull(cBean);
        Map map = cBean.getSimpleBeanMap();
        assertNotNull(map);
        assertEquals(2, map.size());
        Object value = map.get("simpleBean1");
        assertTrue(value instanceof SimpleBean);
        value = map.get("simpleBean2");
        assertTrue(value instanceof SimpleBean);
    }

    @Test
    public void testNestedListProperty() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean1", "org.apache.shiro.config.SimpleBean");
        defs.put("simpleBean2", "org.apache.shiro.config.SimpleBean");
        defs.put("simpleBean3", "org.apache.shiro.config.SimpleBean");
        defs.put("compositeBean", "org.apache.shiro.config.CompositeBean");
        defs.put("compositeBean.simpleBean", "$simpleBean1");
        defs.put("compositeBean.simpleBean.simpleBeans", "$simpleBean2, $simpleBean3");
        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertFalse(CollectionUtils.isEmpty(objects));
        CompositeBean cBean = (CompositeBean) objects.get("compositeBean");
        assertNotNull(cBean);
        SimpleBean nested = cBean.getSimpleBean();
        assertNotNull(nested);
        List<SimpleBean> children = nested.getSimpleBeans();
        assertNotNull(children);
        assertEquals(2, children.size());
    }

    @Test
    public void testFactoryInstantiation() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBeanFactory", "org.apache.shiro.config.SimpleBeanFactory");
        defs.put("simpleBeanFactory.factoryInt", "5");
        defs.put("simpleBeanFactory.factoryString", "someString");
        defs.put("compositeBean", "org.apache.shiro.config.CompositeBean");
        defs.put("compositeBean.simpleBean", "$simpleBeanFactory");

        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertFalse(CollectionUtils.isEmpty(objects));
        CompositeBean compositeBean = (CompositeBean) objects.get("compositeBean");
        SimpleBean bean = compositeBean.getSimpleBean();
        assertNotNull(bean);
        assertEquals(5, bean.getIntProp());
        assertEquals("someString", bean.getStringProp());
    }
}
