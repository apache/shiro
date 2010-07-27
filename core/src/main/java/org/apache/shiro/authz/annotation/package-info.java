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
 * Annotations used to restrict which classes, instances, or methods may be accessed or invoked depending on the
 * caller's access abilities or authentication state.
 * 
 * Since 1.1, all core annotations were extends to accept Target ElementType.TYPE in additon to ElementType.METHOD 
 */
package org.apache.shiro.authz.annotation;
import java.lang.annotation.ElementType;
import java.lang.annotation.Target;

