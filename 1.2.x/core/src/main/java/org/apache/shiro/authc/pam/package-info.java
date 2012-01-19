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
 * Support for <em>PAM</em>, or <b>P</b>luggable <b>A</b>uthentication <b>M</b>odules, which is
 * the capability to authenticate a user against multiple configurable (pluggable) <em>modules</em> (Shiro
 * calls these {@link org.apache.shiro.realm.Realm Realm}s).
 * <p/>
 * The primary class of interest here is the {@link org.apache.shiro.authc.pam.ModularRealmAuthenticator ModularRealmAuthenticator}
 * which is an <code>Authenticator</code> implementation that coordinates authentication attempts across
 * one or more Realm instances.
 * <p/>
 * How the <code>ModularRealmAuthenticator</code> actually coordinates this behavior is configurable based on your
 * application's needs using an injectible
 * {@link AuthenticationStrategy}.
 */
package org.apache.shiro.authc.pam;
