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
package org.apache.ki.spring;

import org.apache.ki.web.servlet.Apache KiFilter;

/**
 * Extension of Apache KiFilter that uses {@link SpringIniWebConfiguration} to configure Apache Ki in a Spring web
 * environment.
 * <p/>
 * Using this class in web.xml essentially enables the following:
 * <pre>&lt;filter&gt;
 * &lt;filter-name&gt;Apache KiFilter&lt;/filter-name&gt;
 * &lt;filter-class&gt;org.jsecurity.web.servlet.Apache KiFilter&lt;/filter-class&gt;
 * &lt;init-param&gt;
 *     &lt;param-name&gt;configClassName&lt;/param-name&gt;
 *     &lt;param-value&gt;org.jsecurity.spring.SpringIniWebConfiguration&lt;param-value&gt;
 * &lt;/init-param&gt;
 * &lt;init-param&gt;
 *     &lt;param-name&gt;config&lt;/param-name&gt;
 *     &lt;param-value&gt;
 *     ... normal .ini config ...
 *     &lt;param-value&gt;
 * &lt;/init-param&gt;
&lt;filter&gt;</pre>
 * <p/>
 * That is, you don't have to specify the additional <code>configClassName</code> <code>init-param</code>.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.2
 */
public class SpringApache KiFilter extends Apache KiFilter {

    //TODO - complete JavaDoc

    /**
     * Default constructor, merely calls
     * <code>{@link #configClassName this.configClassName} = {@link SpringIniWebConfiguration SpringIniWebConfiguration}.class.getName()}</code>.
     */
    public SpringApache KiFilter() {
        this.configClassName = SpringIniWebConfiguration.class.getName();
    }
}
