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
package org.apache.shiro.config.ogdl;

/**
 * Basic String interpolation interface.  Typically implementations will use the Maven/Ant like notation: ${key}, but
 * This is up to the implementation.
 *
 * @since 1.4
 */
public interface Interpolator {

    /**
     * Interpolates <code>value</code> and returns the result.
     * @param value the source text
     * @return the String result of the interpolation, or <code>value</code>, if there was not change.
     */
    String interpolate(String value);
}
