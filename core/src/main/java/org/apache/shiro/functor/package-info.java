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
 * Package containing <a href="http://en.wikipedia.org/wiki/Functor">functor</a> components used for data translation
 * or conversion.  Of particular note is the {@link Translator} interface and its implementations.
 * <p/>
 * Translators are useful in a framework like Shiro which can integrate with many other 3rd-party APIs and
 * frameworks.  A {@code Translator} is convenient when translating from one API concept into another, for
 * example, translating a 3rd-party framework Exception to a Shiro Exception or vice-versa.
 *
 * @since 1.2
 * @see Translator
 */
package org.apache.shiro.functor;