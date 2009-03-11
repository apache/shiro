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

import org.apache.ki.mgt.SecurityManagerFactory;


/**
 * A <code>Configuration</code> is responsible for 'wiring' together all the JSecurity components for an
 * application, such as the {@link org.apache.ki.mgt.SecurityManager SecurityManager}, and any of its
 * dependencies.
 * <p/>
 * Once the SecurityManager is built by the <code>Configuration</code> it is then consulted for all security
 * operations during the application's lifetime.
 * 
 * @author Les Hazlewood
 * @since 0.9
 */
public interface Configuration extends SecurityManagerFactory {
}
