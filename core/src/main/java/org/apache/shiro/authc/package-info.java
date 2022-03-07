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
/**
 * Core interfaces and exceptions concerning Authentication (the act of logging-in).
 * <p/>
 * Shiro abbreviates the word 'AuthentiCation' as <tt>authc</tt> to distinguish it separately from
 * 'AuthoriZation', abbreviated as <tt>authz</tt>.
 * <p/>
 * The primary item of interest in this package is the <tt>Authenticator</tt> interface, which acts as the
 * entry point (facade) to all other other authentication components. Other components, interfaces and
 * exceptions are here to support <tt>Authenticator</tt> implementations.
 */
package org.apache.shiro.authc;
