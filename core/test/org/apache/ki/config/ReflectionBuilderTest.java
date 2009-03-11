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
package org.apache.ki.config;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.*;
import org.junit.Test;
import org.apache.ki.config.ConfigurationException;
import org.apache.ki.config.ReflectionBuilder;
import org.apache.ki.config.UnresolveableReferenceException;

/**
 * @author Les Hazlewood
 * @since Aug 5, 2008 9:53:00 AM
 */
public class ReflectionBuilderTest {

    @Test
    public void testSimpleConfig() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("compositeBean", "org.apache.ki.config.CompositeBean");
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
        defs.put("compositeBean", "org.apache.ki.config.CompositeBean");
        defs.put("compositeBean.stringProp", "\\$500");

        ReflectionBuilder builder = new ReflectionBuilder();
        Map beans = builder.buildObjects(defs);

        CompositeBean compositeBean = (CompositeBean) beans.get("compositeBean");
        assertEquals(compositeBean.getStringProp(), "$500");
    }

    @Test
    public void testObjectReferenceConfig() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean", "org.apache.ki.config.SimpleBean");
        defs.put("simpleBean.intProp", "101");
        defs.put("compositeBean", "org.apache.ki.config.CompositeBean");
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
        defs.put("simpleBean", "org.apache.ki.config.SimpleBean");
        defs.put("compositeBean", "org.apache.ki.config.CompositeBean");
        defs.put("compositeBean.simpleBean", "simpleBean");
        ReflectionBuilder builder = new ReflectionBuilder();
        builder.buildObjects(defs);
    }

    @Test(expected = UnresolveableReferenceException.class)
    public void testObjectReferenceConfigWithInvalidReference() {
        Map<String, String> defs = new LinkedHashMap<String, String>();
        defs.put("simpleBean", "org.apache.ki.config.SimpleBean");
        defs.put("compositeBean", "org.apache.ki.config.CompositeBean");
        defs.put("compositeBean.simpleBean", "$foo");
        ReflectionBuilder builder = new ReflectionBuilder();
        builder.buildObjects(defs);
    }
}
