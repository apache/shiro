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

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;

@RunWith(PaxExam.class)
public class NamedBeanMapTest {
    
    @Inject
    private BeanManager beanManager;

    @Test
    public void findNamedBeans() {
        NamedBeanMap namedBeanMap = new NamedBeanMap(beanManager);
        assertThat(namedBeanMap.isEmpty(), is(false));
        
        List<String> origins = new ArrayList<String>();
        for (Map.Entry<String, Object> entry : namedBeanMap.entrySet()) {
            Object object = entry.getValue();
            if (object instanceof Food) {
                Food food = (Food) object;
                origins.add(food.getOrigin());
            }
        }
        assertThat(origins.size(), is(3));
        assertThat(origins, hasItems("Germany", "India", "Italy"));
    }
}
