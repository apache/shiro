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

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author Les Hazlewood
 * @since Aug 5, 2008 10:17:37 AM
 */
@SuppressWarnings({"UnusedDeclaration"})
public class CompositeBean {

    private String stringProp;
    private boolean booleanProp;
    private int intProp;
    private SimpleBean simpleBean;

    private Set<SimpleBean> simpleBeanSet;
    private List<SimpleBean> simpleBeanList;
    private Collection<SimpleBean> simpleBeanCollection;
    private Map<String, SimpleBean> simpleBeanMap;

    public CompositeBean() {
    }

    public String getStringProp() {
        return stringProp;
    }

    public void setStringProp(String stringProp) {
        this.stringProp = stringProp;
    }

    public boolean isBooleanProp() {
        return booleanProp;
    }

    public void setBooleanProp(boolean booleanProp) {
        this.booleanProp = booleanProp;
    }

    public int getIntProp() {
        return intProp;
    }

    public void setIntProp(int intProp) {
        this.intProp = intProp;
    }

    public SimpleBean getSimpleBean() {
        return simpleBean;
    }

    public void setSimpleBean(SimpleBean simpleBean) {
        this.simpleBean = simpleBean;
    }

    public Set<SimpleBean> getSimpleBeanSet() {
        return simpleBeanSet;
    }

    public void setSimpleBeanSet(Set<SimpleBean> simpleBeanSet) {
        this.simpleBeanSet = simpleBeanSet;
    }

    public List<SimpleBean> getSimpleBeanList() {
        return simpleBeanList;
    }

    public void setSimpleBeanList(List<SimpleBean> simpleBeanList) {
        this.simpleBeanList = simpleBeanList;
    }

    public Collection<SimpleBean> getSimpleBeanCollection() {
        return simpleBeanCollection;
    }

    public void setSimpleBeanCollection(Collection<SimpleBean> simpleBeanCollection) {
        this.simpleBeanCollection = simpleBeanCollection;
    }

    public Map<String, SimpleBean> getSimpleBeanMap() {
        return simpleBeanMap;
    }

    public void setSimpleBeanMap(Map<String, SimpleBean> simpleBeanMap) {
        this.simpleBeanMap = simpleBeanMap;
    }
}
