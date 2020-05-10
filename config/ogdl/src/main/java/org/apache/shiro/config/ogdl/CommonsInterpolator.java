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
package org.apache.shiro.config.ogdl;

import org.apache.commons.configuration2.interpol.ConfigurationInterpolator;
import org.apache.commons.configuration2.interpol.ConstantLookup;
import org.apache.commons.configuration2.interpol.EnvironmentLookup;
import org.apache.commons.configuration2.interpol.SystemPropertiesLookup;

/**
 * Commons-Config interpolation wrapper. This implementation uses a {@link ConfigurationInterpolator} with the default
 * lookup: <code>sys</code> (system properties), <code>env</code> (environment variables>, and <code>const</code> (constants).
 *
 * <table>
 *     <tr>
 *         <th>lookup</th>
 *         <th>example</th>
 *         <th>value</th>
 *     </tr>
 *     <tr>
 *         <td>sys</td>
 *         <td>${sys:os.name}</td>
 *         <td>mac os x</td>
 *     </tr>
 *     <tr>
 *         <td>env</td>
 *         <td>${env:EDITOR}</td>
 *         <td>vi</td>
 *     </tr>
 *     <tr>
 *         <td>const</td>
 *         <td>${const:java.awt.event.KeyEvent.VK_ENTER}</td>
 *         <td>\n</td>
 *     </tr>
 * </table>
 *
 * @see ConfigurationInterpolator
 * @since 1.4
 */
public class CommonsInterpolator implements Interpolator {

    final private ConfigurationInterpolator interpolator;

    public CommonsInterpolator() {
        this.interpolator = new ConfigurationInterpolator();

        interpolator.registerLookup("const", new ConstantLookup());
        interpolator.addDefaultLookup(new SystemPropertiesLookup());
        interpolator.addDefaultLookup(new EnvironmentLookup());
    }

    @Override
    public String interpolate(String value) {
        return (String) interpolator.interpolate(value);
    }

    public ConfigurationInterpolator getConfigurationInterpolator() {
        return interpolator;
    }
}
