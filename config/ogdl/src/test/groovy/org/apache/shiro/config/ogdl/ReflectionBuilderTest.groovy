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
package org.apache.shiro.config.ogdl

import org.apache.shiro.config.ogdl.beans.InitCountBean
import org.apache.shiro.lang.codec.Base64
import org.apache.shiro.lang.codec.CodecSupport
import org.apache.shiro.lang.codec.Hex
import org.apache.shiro.config.ConfigurationException
import org.apache.shiro.config.Ini
import org.apache.shiro.config.ogdl.event.BeanEvent
import org.junit.Test

import java.util.concurrent.ConcurrentHashMap

import static org.junit.Assert.*
import static org.hamcrest.Matchers.*

/**
 * Unit tests for the {@link org.apache.shiro.config.ogdl.ReflectionBuilder} implementation.
 */
@SuppressWarnings("GrMethodMayBeStatic")
class ReflectionBuilderTest {

    @Test
    void testStandardPropertyAssignment() {
        ReflectionBuilder builder = new ReflectionBuilder();

        CompositeBean cBean = new CompositeBean();
        builder.applyProperty(cBean, 'stringProp', 'hello world')
        builder.applyProperty(cBean, 'booleanProp', true)
        builder.applyProperty(cBean, 'intProp', 42)
        builder.applyProperty(cBean, 'simpleBean', new SimpleBean())

        assertTrue cBean.stringProp == 'hello world'
        assertTrue cBean.booleanProp
        assertTrue cBean.intProp == 42
        assertTrue cBean.simpleBean instanceof SimpleBean
    }

    @Test
    void testMapEntryAssignment() {
        ReflectionBuilder builder = new ReflectionBuilder();

        CompositeBean cBean = new CompositeBean();
        cBean.simpleBeanMap = ['simpleBean1': new SimpleBean()]

        builder.applyProperty(cBean, 'simpleBeanMap[simpleBean2]', new SimpleBean())

        assertTrue cBean.simpleBeanMap['simpleBean2'] instanceof SimpleBean
    }

    @Test
    void testArrayEntryAssignment() {
        ReflectionBuilder builder = new ReflectionBuilder();

        CompositeBean cBean = new CompositeBean();
        cBean.compositeBeanArray = new CompositeBean[1];

        builder.applyProperty(cBean, 'compositeBeanArray[0]', new CompositeBean())

        assertTrue cBean.compositeBeanArray[0] instanceof CompositeBean
    }

    @Test
    void testNestedPathAssignment() {
        ReflectionBuilder builder = new ReflectionBuilder();

        CompositeBean cbean1 = new CompositeBean('cbean1');
        cbean1.compositeBeanMap = ['cbean2': new CompositeBean('cbean2')]
        cbean1.compositeBeanMap['cbean2'].compositeBeanArray = new CompositeBean[2];

        builder.applyProperty(cbean1, "compositeBeanMap[cbean2].compositeBeanArray[0]", new CompositeBean('cbean3'))
        builder.applyProperty(cbean1, "compositeBeanMap[cbean2].compositeBeanArray[0].simpleBean", new SimpleBean('sbean1'))

        assertTrue cbean1.compositeBeanMap['cbean2'].compositeBeanArray[0].name == 'cbean3'
        assertTrue cbean1.compositeBeanMap['cbean2'].compositeBeanArray[0].simpleBean.name == 'sbean1'
    }

    @Test
    //asserts SHIRO-305: https://issues.apache.org/jira/browse/SHIRO-305
    void testNestedMapAssignmentWithPeriodDelimitedKeys() {
        def ini = new Ini()
        ini.load('''
            simpleBean = org.apache.shiro.config.ogdl.SimpleBean
            simpleBean.mapProp[java.naming.security.protocol] = ssl
            simpleBean.mapProp[com.sun.jndi.ldap.connect.pool] = true
            simpleBean.mapProp[com.sun.jndi.ldap.connect.pool.protocol] = plain ssl
        ''')
        def builder = new ReflectionBuilder()
        def objects = builder.buildObjects(ini.getSections().iterator().next())

        assertFalse objects.isEmpty()
        def simpleBean = objects['simpleBean'] as SimpleBean
        assertEquals 'ssl', simpleBean.mapProp['java.naming.security.protocol']
        assertEquals 'true', simpleBean.mapProp['com.sun.jndi.ldap.connect.pool']
        assertEquals 'plain ssl', simpleBean.mapProp['com.sun.jndi.ldap.connect.pool.protocol']
    }

    @Test
    void testSimpleConfig() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
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
    void testWithConfiguredNullValue() {
        Map<String,Object> defaults = new LinkedHashMap<String,Object>();
        CompositeBean cBean = new CompositeBean();
        cBean.setSimpleBean(new SimpleBean());
        defaults.put("compositeBean", cBean);

        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("compositeBean.intProp", "42");
        defs.put("compositeBean.booleanProp", "true");
        defs.put("compositeBean.stringProp", "test");
        defs.put("compositeBean.simpleBean", "null");

        ReflectionBuilder builder = new ReflectionBuilder(defaults);
        Map beans = builder.buildObjects(defs);

        CompositeBean compositeBean = (CompositeBean) beans.get("compositeBean");
        assertNotNull(compositeBean);
        assertTrue(compositeBean.isBooleanProp());
        assertEquals(compositeBean.getIntProp(), 42);
        assertEquals("test", compositeBean.getStringProp());
        assertNull(compositeBean.getSimpleBean());
    }

    @Test
    void testWithConfiguredNullLiteralValue() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
        defs.put("compositeBean.intProp", "42");
        defs.put("compositeBean.booleanProp", "true");
        defs.put("compositeBean.stringProp", "\"null\"");

        ReflectionBuilder builder = new ReflectionBuilder();
        Map beans = builder.buildObjects(defs);

        CompositeBean compositeBean = (CompositeBean) beans.get("compositeBean");
        assertNotNull(compositeBean);
        assertTrue(compositeBean.isBooleanProp());
        assertEquals(compositeBean.getIntProp(), 42);
        assertEquals("null", compositeBean.getStringProp());
    }

    @Test
    void testWithConfiguredEmptyStringValue() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
        defs.put("compositeBean.intProp", "42");
        defs.put("compositeBean.booleanProp", "true");
        defs.put("compositeBean.stringProp", "\"\"");

        ReflectionBuilder builder = new ReflectionBuilder();
        Map beans = builder.buildObjects(defs);

        CompositeBean compositeBean = (CompositeBean) beans.get("compositeBean");
        assertNotNull(compositeBean);
        assertTrue(compositeBean.isBooleanProp());
        assertEquals(compositeBean.getIntProp(), 42);
        assertEquals("", compositeBean.getStringProp());
    }

    @Test
    void testWithConfiguredEmptyStringLiteralValue() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
        defs.put("compositeBean.intProp", "42");
        defs.put("compositeBean.booleanProp", "true");
        defs.put("compositeBean.stringProp", "\"\"\"\"");

        ReflectionBuilder builder = new ReflectionBuilder();
        Map beans = builder.buildObjects(defs);

        CompositeBean compositeBean = (CompositeBean) beans.get("compositeBean");
        assertNotNull(compositeBean);
        assertTrue(compositeBean.isBooleanProp());
        assertEquals(compositeBean.getIntProp(), 42);
        assertEquals("\"\"", compositeBean.getStringProp());
    }

    @Test
    void testSimpleConfigWithDollarSignStringValue() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
        defs.put("compositeBean.stringProp", '\\$500');

        ReflectionBuilder builder = new ReflectionBuilder();
        Map beans = builder.buildObjects(defs);

        CompositeBean compositeBean = (CompositeBean) beans.get("compositeBean");
        assertEquals(compositeBean.getStringProp(), '$500');
    }

    @Test
    void testObjectReferenceConfig() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("simpleBean.intProp", "101");
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
        defs.put("compositeBean.stringProp", "blah");
        defs.put("compositeBean.simpleBean", '$simpleBean');

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

    @Test
    void testObjectReferenceConfigWithTypeMismatch() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
        defs.put("compositeBean.simpleBean", "simpleBean");
        ReflectionBuilder builder = new ReflectionBuilder();
        try {
            builder.buildObjects(defs);
            "Should have encountered an " + ConfigurationException.class.name
        } catch (ConfigurationException expected) {
        }
    }

    @Test
    void testObjectReferenceConfigWithInvalidReference() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
        defs.put("compositeBean.simpleBean", '$foo');
        ReflectionBuilder builder = new ReflectionBuilder();
        try {
            builder.buildObjects(defs);
            fail "should have encountered an " + UnresolveableReferenceException.class.name
        } catch (UnresolveableReferenceException expected) {
        }
    }

    @Test
    void testSetProperty() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean1", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("simpleBean2", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
        defs.put("compositeBean.simpleBeanSet", '$simpleBean1, $simpleBean2, $simpleBean2');
        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertThat(objects, aMapWithSize(greaterThan(0)))
        CompositeBean cBean = (CompositeBean) objects.get("compositeBean");
        assertNotNull(cBean);
        Set<SimpleBean> simpleBeans = cBean.getSimpleBeanSet();
        assertNotNull(simpleBeans);
        assertEquals(2, simpleBeans.size());
    }

    @Test
    //SHIRO-423
    void testSetPropertyWithReferencedSet() {
        def set = [new SimpleBean('foo'), new SimpleBean('bar')] as Set

        def defs = [
                compositeBean: 'org.apache.shiro.config.ogdl.CompositeBean',
                'compositeBean.simpleBeanSet': '$set'
        ]

        ReflectionBuilder builder = new ReflectionBuilder(['set': set]);
        Map objects = builder.buildObjects(defs);
        assertThat(objects, aMapWithSize(greaterThan(0)))
        CompositeBean cBean = (CompositeBean) objects.get("compositeBean");
        assertNotNull(cBean);
        Set<SimpleBean> simpleBeans = cBean.getSimpleBeanSet();
        assertNotNull(simpleBeans);
        assertSame set, simpleBeans
        assertEquals(2, simpleBeans.size());
        def i = simpleBeans.iterator()
        assertEquals 'foo', i.next().name
        assertEquals 'bar', i.next().name
    }

    @Test
    void testListProperty() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean1", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("simpleBean2", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
        defs.put("compositeBean.simpleBeanList", '$simpleBean1, $simpleBean2, $simpleBean2');
        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertThat(objects, aMapWithSize(greaterThan(0)))
        CompositeBean cBean = (CompositeBean) objects.get("compositeBean");
        assertNotNull(cBean);
        List<SimpleBean> simpleBeans = cBean.getSimpleBeanList();
        assertNotNull(simpleBeans);
        assertEquals(3, simpleBeans.size());
    }

    @Test
    //SHIRO-423
    void testListPropertyWithReferencedList() {
        List list = [new SimpleBean('foo'), new SimpleBean('bar')] as List

        def defs = [
                compositeBean: 'org.apache.shiro.config.ogdl.CompositeBean',
                'compositeBean.simpleBeanList': '$list'
        ]

        ReflectionBuilder builder = new ReflectionBuilder(['list': list]);
        Map objects = builder.buildObjects(defs);
        assertThat(objects, aMapWithSize(greaterThan(0)))
        CompositeBean cBean = (CompositeBean) objects.get("compositeBean");
        assertNotNull(cBean);
        def simpleBeans = cBean.getSimpleBeanList();
        assertNotNull(simpleBeans);
        assertSame list, simpleBeans
        assertEquals(2, simpleBeans.size());
        assertEquals 'foo', simpleBeans[0].name
        assertEquals 'bar', simpleBeans[1].name
    }

    @Test
    void testCollectionProperty() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean1", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("simpleBean2", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
        defs.put("compositeBean.simpleBeanCollection", '$simpleBean1, $simpleBean2, $simpleBean2');
        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertThat(objects, aMapWithSize(greaterThan(0)))
        CompositeBean cBean = (CompositeBean) objects.get("compositeBean");
        assertNotNull(cBean);
        Collection<SimpleBean> simpleBeans = cBean.getSimpleBeanCollection();
        assertNotNull(simpleBeans);
        assertTrue(simpleBeans instanceof List);
        assertEquals(3, simpleBeans.size());
    }

    @Test
    //SHIRO-423
    void testCollectionPropertyWithReferencedCollection() {
        def c = [new SimpleBean('foo'), new SimpleBean('bar')]

        def defs = [
                compositeBean: 'org.apache.shiro.config.ogdl.CompositeBean',
                'compositeBean.simpleBeanCollection': '$collection'
        ]

        ReflectionBuilder builder = new ReflectionBuilder(['collection': c]);
        Map objects = builder.buildObjects(defs);
        assertThat(objects, aMapWithSize(greaterThan(0)))
        CompositeBean cBean = (CompositeBean) objects.get("compositeBean");
        assertNotNull(cBean);
        def simpleBeans = cBean.getSimpleBeanCollection();
        assertNotNull(simpleBeans);
        assertSame c, simpleBeans
        assertEquals(2, simpleBeans.size());
        def i  = simpleBeans.iterator()
        assertEquals 'foo', i.next().name
        assertEquals 'bar', i.next().name
    }

    @Test
    void testByteArrayHexProperty() {
        String source = "Hello, world.";
        byte[] bytes = CodecSupport.toBytes(source);
        String hex = Hex.encodeToString(bytes);
        String hexValue = "0x" + hex;

        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("simpleBean.byteArrayProp", hexValue);
        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertThat(objects, aMapWithSize(greaterThan(0)))
        SimpleBean bean = (SimpleBean) objects.get("simpleBean");
        assertNotNull(bean);
        byte[] beanBytes = bean.getByteArrayProp();
        assertNotNull(beanBytes);
        String reconstituted = CodecSupport.toString(beanBytes);
        assertEquals(source, reconstituted);
    }

    @Test
    void testByteArrayBase64Property() {
        String source = "Hello, world.";
        byte[] bytes = CodecSupport.toBytes(source);
        String base64 = Base64.encodeToString(bytes);

        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean", "org.apache.shiro.config.ogdl.SimpleBean");
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
    void testMapProperty() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean1", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("simpleBean2", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
        defs.put("compositeBean.simpleBeanMap", 'simpleBean1:$simpleBean1, simpleBean2:$simpleBean2');
        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertThat(objects, aMapWithSize(greaterThan(0)))
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
    //SHIRO-423
    void testMapPropertyWithReferencedMap() {
        def map = ['foo': new SimpleBean('foo'), 'bar': new SimpleBean('bar')]

        def defs = [
                compositeBean: 'org.apache.shiro.config.ogdl.CompositeBean',
                'compositeBean.simpleBeanMap': '$map'
        ]

        ReflectionBuilder builder = new ReflectionBuilder(['map': map]);
        Map objects = builder.buildObjects(defs);
        assertThat(objects, aMapWithSize(greaterThan(0)))
        CompositeBean cBean = (CompositeBean) objects.get("compositeBean");
        assertNotNull(cBean);
        def simpleBeansMap = cBean.getSimpleBeanMap();
        assertNotNull(simpleBeansMap);
        assertSame map, simpleBeansMap
        assertEquals(2, simpleBeansMap.size());
        assertEquals 'foo', simpleBeansMap['foo'].name
        assertEquals 'bar', simpleBeansMap['bar'].name
    }

    @Test
    void testNestedListProperty() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean1", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("simpleBean2", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("simpleBean3", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
        defs.put("compositeBean.simpleBean", '$simpleBean1');
        defs.put("compositeBean.simpleBean.simpleBeans", '$simpleBean2, $simpleBean3');
        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertThat(objects, aMapWithSize(greaterThan(0)))
        CompositeBean cBean = (CompositeBean) objects.get("compositeBean");
        assertNotNull(cBean);
        SimpleBean nested = cBean.getSimpleBean();
        assertNotNull(nested);
        List<SimpleBean> children = nested.getSimpleBeans();
        assertNotNull(children);
        assertEquals(2, children.size());
    }

    @Test
    //asserts SHIRO-413
    void testInitializable() {
        def defs = [
                initializableBean: 'org.apache.shiro.config.ogdl.InitializableBean'
        ]
        def builder = new ReflectionBuilder()
        def objects = builder.buildObjects(defs)
        def bean = objects.get('initializableBean') as InitializableBean
        assertTrue bean.isInitialized()
    }

    @Test
    void testFactoryInstantiation() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBeanFactory", "org.apache.shiro.config.ogdl.SimpleBeanFactory");
        defs.put("simpleBeanFactory.factoryInt", "5");
        defs.put("simpleBeanFactory.factoryString", "someString");
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
        defs.put("compositeBean.simpleBean", '$simpleBeanFactory');

        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertThat(objects, aMapWithSize(greaterThan(0)))
        CompositeBean compositeBean = (CompositeBean) objects.get("compositeBean");
        SimpleBean bean = compositeBean.getSimpleBean();
        assertNotNull(bean);
        assertEquals(5, bean.getIntProp());
        assertEquals("someString", bean.getStringProp());
    }

    @Test
    void testBeanListeners() {

        def ini = new Ini();
        ini.load '''
            loggingListener = org.apache.shiro.config.ogdl.event.LoggingBeanEventListener
            listenerOne = org.apache.shiro.config.ogdl.RecordingBeanListener
            listenerTwo = org.apache.shiro.config.ogdl.RecordingBeanListener

            simpleBeanFactory = org.apache.shiro.config.ogdl.SimpleBeanFactory
            simpleBeanFactory.factoryInt = 5
            simpleBeanFactory.factoryString = someString

            compositeBean = org.apache.shiro.config.ogdl.CompositeBean
            compositeBean.simpleBean = $simpleBeanFactory
        '''

        ReflectionBuilder builder = new ReflectionBuilder();
        Map<String, ?> objects = builder.buildObjects(ini.getSections().iterator().next());
        assertThat(objects, aMapWithSize(greaterThan(0)))

        assertInstantiatedEvents("listenerOne", objects, 4) //3 beans following + its own instantiated event
        assertConfiguredEvents("listenerOne", objects, 4) //3 beans following + its own configured event
        assertInitializedEvents("listenerOne", objects, 4) //3 beans following + its own initialized event

        assertInstantiatedEvents("listenerTwo", objects, 3) //2 beans following + its own instantiated event
        assertConfiguredEvents("listenerTwo", objects, 3); //2 beans following + its own configured event
        assertInitializedEvents("listenerTwo", objects, 3); //2 beans following + its own initialized event

        builder.destroy();

        assertDestroyedEvents("listenerOne", objects, 4); //3 beans defined after it + its own destroyed event
        assertDestroyedEvents("listenerTwo", objects, 3); //2 beans defined after it + its own destroyed event
    }

    /**
     * SHIRO-739
     */
    @Test
    void testEnum() {
        def ini = new Ini()
        ini.load '''
            simpleBean = org.apache.shiro.config.ogdl.SimpleBean
            simpleBean.name = testEnum
            simpleBean.simpleEnum = FOO
        '''

        ReflectionBuilder builder = new ReflectionBuilder();
        Map<String, ?> objects = builder.buildObjects(ini.getSections().iterator().next());
        assertThat(objects, aMapWithSize(greaterThan(0)))

        SimpleBean bean = objects.get("simpleBean")
        assertThat(bean.name, is("testEnum"))
        assertThat(bean.simpleEnum, is(SimpleEnum.FOO))
    }

    /**
     * @since 1.4
     */
    @Test
    void testSimpleInterpolation() {

        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBeanFactory", "org.apache.shiro.config.ogdl.SimpleBeanFactory");
        defs.put("simpleBeanFactory.factoryInt", "5");
        defs.put("simpleBeanFactory.factoryString", "\${os.name}");
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
        defs.put("compositeBean.simpleBean", '$simpleBeanFactory');

        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertThat(objects, aMapWithSize(greaterThan(0)))
        CompositeBean compositeBean = (CompositeBean) objects.get("compositeBean");
        SimpleBean bean = compositeBean.getSimpleBean();
        assertNotNull(bean);
        assertEquals(5, bean.getIntProp());
        assertEquals(System.getProperty("os.name"), bean.getStringProp());

    }

    /**
     * @since 1.4
     */
    @Test
    void testInterpolationForMapKeysAndLists() {

        // using os.name and os.arch because they are available on every system

        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean1", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("simpleBean1.stringList", "\${os.name}, \${os.arch}");
        defs.put("simpleBean2", "org.apache.shiro.config.ogdl.SimpleBean");
        defs.put("compositeBean", "org.apache.shiro.config.ogdl.CompositeBean");
        defs.put("compositeBean.simpleBeanMap", '\${os.name}:$simpleBean1, two:$simpleBean2');

        ReflectionBuilder builder = new ReflectionBuilder();
        Map objects = builder.buildObjects(defs);
        assertThat(objects, aMapWithSize(greaterThan(0)))

        CompositeBean compositeBean = (CompositeBean) objects.get("compositeBean");
        assertNotNull(compositeBean);

        def beanMap = compositeBean.getSimpleBeanMap()
        assertNotNull(beanMap)
        assertThat beanMap, allOf(hasKey(System.getProperty("os.name")), hasKey("two"), aMapWithSize(2))

        def beanOne = beanMap.get(System.getProperty("os.name"))
        assertThat beanOne.stringList, allOf(hasItem(System.getProperty("os.name")), hasItem(System.getProperty("os.arch")), hasSize(2))

        assertNotNull(beanMap.get("two"))
    }

    @Test
    void testNotMultipleInitialization() {
        // given
        Map<String, String> defs = new ConcurrentHashMap<>()
        defs.put("initcountbean", InitCountBean.getCanonicalName())
        ReflectionBuilder builder = new ReflectionBuilder()

        // when
        builder.buildObjects(defs)

        // then
        assertEquals(1, InitCountBean.getInitCount())
        InitCountBean.resetCount()
    }

    @Test
    void testNotMultipleInitializationWithNullFirst() {
        // given
        Map<String, String> defs = new ConcurrentHashMap<>()
        defs.put("initcountbean", InitCountBean.getCanonicalName())
        ReflectionBuilder builder = new ReflectionBuilder()

        // when
        builder.buildObjects(null)
        builder.buildObjects(defs)

        // then
        assertEquals(1, InitCountBean.getInitCount())
        InitCountBean.resetCount()
    }

    void assertInstantiatedEvents(String name, Map<String, ?> objects, int expected) {
        def bean = objects.get(name) as RecordingBeanListener
        def events = bean.getInstantiatedEvents()
        assertEquals(expected, events.size())

        checkType(name, events, "simpleBeanFactory", SimpleBeanFactory);
        checkType(name, events, "compositeBean", CompositeBean);
    }

    void assertConfiguredEvents(String name, Map<String, ?> objects, int expected) {
        def bean = objects.get(name) as RecordingBeanListener
        def events = bean.getConfiguredEvents();
        assertEquals(expected, events.size())

        checkType(name, events, "listenerTwo", RecordingBeanListener);
        checkType(name, events, "simpleBeanFactory", SimpleBeanFactory);
        checkType(name, events, "compositeBean", CompositeBean);
    }

    void assertInitializedEvents(String name, Map<String, ?> objects, int expected) {
        def bean = objects.get(name) as RecordingBeanListener
        def events = bean.getInitializedEvents();
        assertEquals(expected, events.size())

        checkType(name, events, "listenerTwo", RecordingBeanListener);
        checkType(name, events, "simpleBeanFactory", SimpleBeanFactory);
        checkType(name, events, "compositeBean", CompositeBean);
    }

    void assertDestroyedEvents(String name, Map<String, ?> objects, int expected) {
        def bean = objects.get(name) as RecordingBeanListener
        def events = bean.getDestroyedEvents();
        assertEquals(expected, events.size())

        if (expected > 3) {
            checkType(name, events, "listenerOne", RecordingBeanListener);
        }
        checkType(name, events, "listenerTwo", RecordingBeanListener);
        checkType(name, events, "simpleBeanFactory", SimpleBeanFactory);
        checkType(name, events, "compositeBean", CompositeBean);
    }

    void checkType(String instanceName, List<? extends BeanEvent> events, String name, Class<?> expectedType) {
        for(BeanEvent event: events) {
            if(event.getBeanName().equals(name)) {
                assertTrue("Notification for bean " + name + " did not provide an instance of " + expectedType
                        + " to listener " + instanceName,
                expectedType.isInstance(event.getBean()))
                return;
            }
        }
        fail("No bean named " + name + " was ever notified to listener " + instanceName + ".");
    }
}
