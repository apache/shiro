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
package org.apache.shiro.config.event;

/**
 * Extension point that provides for notification of lifecycle events in the bean configuration process.  This is an
 * extension point of the (typically) ini-based bean instantiation strategy used by default by shiro.  It is intended
 * as a bare-bones corollary to the more advanced lifecycle facilities offered in full-fledged dependency injection
 * frameworks.
 *
 * The type of event is determined by the type of the beanEvent object.  Use of {@see BeanListenerSupport} is
 * recommended.
 */
public interface BeanListener {
    void onBeanEvent(BeanEvent beanEvent);
}
