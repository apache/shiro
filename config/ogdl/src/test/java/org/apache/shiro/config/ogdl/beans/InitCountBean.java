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
package org.apache.shiro.config.ogdl.beans;

import org.apache.shiro.lang.ShiroException;
import org.apache.shiro.lang.util.Initializable;

import java.util.StringJoiner;
import java.util.concurrent.atomic.LongAdder;

public class InitCountBean implements Initializable {
    private static final LongAdder INIT_COUNT = new LongAdder();

    public InitCountBean() {
        super();
    }

    public static long getInitCount() {
        return INIT_COUNT.longValue();
    }

    public static void resetCount() {
        INIT_COUNT.reset();
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", InitCountBean.class.getSimpleName() + "[", "]")
                .add("INIT_COUNT=" + getInitCount())
                .toString();
    }

    @Override
    public void init() throws ShiroException {
        INIT_COUNT.increment();
    }
}
