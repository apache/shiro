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
package org.apache.shiro.event;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Indicates a method is an event consumer.  The method must have a single argument and the argument's type determines
 * what type of events should be delivered to the method for consumption.
 * <p/>
 * For example:
 * <pre>
 * &#64;Subscribe
 * public void onSomeEvent(SomeEvent event) { ... }
 * </pre>
 * <p/>
 * Because the method argument is declared as a {@code SomeEvent} type, the method will be called by the event
 * dispatcher whenever a {@code SomeEvent} instance (or one of its subclass instances that is not already registered)
 * is published.
 *
 * @since 1.3
 */
@Retention(value = RetentionPolicy.RUNTIME)
@Target(value = ElementType.METHOD)
public @interface Subscribe {
}
