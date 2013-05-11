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
package org.apache.shiro.cache;

/**
 * Interface implemented by components that utilize a CacheManager and wish that CacheManager to be supplied if
 * one is available.
 *
 * <p>This is used so internal security components that use a CacheManager can be injected with it instead of having
 * to create one on their own.
 *
 * @since 0.9
 */
public interface CacheManagerAware {

    /**
     * Sets the available CacheManager instance on this component.
     *
     * @param cacheManager the CacheManager instance to set on this component.
     */
    void setCacheManager(CacheManager cacheManager);
}
