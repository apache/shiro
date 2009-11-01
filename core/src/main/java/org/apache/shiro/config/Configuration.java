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

import org.apache.shiro.mgt.SecurityManagerFactory;


/**
 * A <code>Configuration</code> is responsible for 'wiring' together all the Shiro components for an
 * application, such as the {@link org.apache.shiro.mgt.SecurityManager SecurityManager}, and any of its
 * dependencies.
 * <p/>
 * Once the SecurityManager is built by the <code>Configuration</code> it is then consulted for all security
 * operations during the application's lifetime.
 * <p/>
 * <b>Do not use this! It will be removed prior to 1.0 final!</b>
 *
 * @author Les Hazlewood
 * @since 0.9
 * @deprecated use {@link org.apache.shiro.util.Factory} implementations to generate the Shiro
 *             components. See {@link org.apache.shiro.config.IniSecurityManagerFactory} as an example.
 *             <b>Will be removed prior to 1.0 final!</b>
 */
@Deprecated
public interface Configuration extends SecurityManagerFactory {
}
