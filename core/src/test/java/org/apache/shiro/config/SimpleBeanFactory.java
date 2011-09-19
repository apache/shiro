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

import org.apache.shiro.util.Factory;

public class SimpleBeanFactory implements Factory<SimpleBean> {
    private int factoryInt;
    private String factoryString;

    public SimpleBean getInstance() {
        final SimpleBean simpleBean = new SimpleBean();
        simpleBean.setIntProp(factoryInt);
        simpleBean.setStringProp(factoryString);
        return simpleBean;
    }

    public int getFactoryInt() {
        return factoryInt;
    }

    public void setFactoryInt(int factoryInt) {
        this.factoryInt = factoryInt;
    }

    public String getFactoryString() {
        return factoryString;
    }

    public void setFactoryString(String factoryString) {
        this.factoryString = factoryString;
    }
}
