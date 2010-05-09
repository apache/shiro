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

import java.util.List;

/**
 * @author Les Hazlewood
 * @since 1.0
 */
public class SimpleBean {

    private String stringProp = null;
    private int intProp;
    private byte[] byteArrayProp = null;

    private List<SimpleBean> simpleBeans;

    public SimpleBean() {
    }

    public String getStringProp() {
        return stringProp;
    }

    public void setStringProp(String stringProp) {
        this.stringProp = stringProp;
    }

    public int getIntProp() {
        return intProp;
    }

    public void setIntProp(int intProp) {
        this.intProp = intProp;
    }

    public byte[] getByteArrayProp() {
        return byteArrayProp;
    }

    public void setByteArrayProp(byte[] byteArrayProp) {
        this.byteArrayProp = byteArrayProp;
    }

    public List<SimpleBean> getSimpleBeans() {
        return simpleBeans;
    }

    public void setSimpleBeans(List<SimpleBean> simpleBeans) {
        this.simpleBeans = simpleBeans;
    }
}
