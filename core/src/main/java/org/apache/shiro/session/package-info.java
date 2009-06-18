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
 * Components related to managing sessions, the time-based data contexts in which a Subject
 * interacts with an application.
 * <p/>
 * Sessions in Shiro are completely POJO-based and do not <em>require</em> an application to use Web-based
 * or EJB-based session management infrastructure - the client and/or server technoloy is irrelevent in
 * Shiro's architecture, allowing session management to be employed in the smallest standalone application
 * to the largest enterprise deployments.
 * <p/>
 * This design decision opens up a new world to Java applications - most notably the ability to participate in
 * a session regardless if the client is using HTTP, custom sockets, web services, or even non-Java progamming
 * languages. Aside from Shiro, there is currently no technology in Java today allows this heterogenous
 * client-session capability.
 * <p/>
 * Also because of this freedom, Shiro naturally supports Single Sign-On for any application as well, using
 * this heterogeneous session support.
 */
package org.apache.shiro.session;
