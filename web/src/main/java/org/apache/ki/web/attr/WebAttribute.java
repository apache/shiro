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
package org.apache.ki.web.attr;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * A <tt>WebAttribute</tt> is a storage mechanism for a single object accessible during a web request.
 *
 * <p>It is used to make objects associated with the transient request persistent beyond the request so that they can
 * be retrieved at a later time.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public interface WebAttribute<T> {

    //TODO - complete JavaDoc

    T retrieveValue(ServletRequest request, ServletResponse response);

    void storeValue(T value, ServletRequest request, ServletResponse response);

    void removeValue(ServletRequest request, ServletResponse response);
}
