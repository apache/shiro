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
package org.apache.shiro.authc;

/**
 * <p>An extension of the {@link AuthenticationInfo} interface to be implemented by
 * classes that support merging with other {@link AuthenticationInfo} instances.</p>
 *
 * <p>This allows an instance of this class to be an <em>aggregation</em>, or <em>composition</em> of account data
 * from across multiple <code>Realm</code>s <tt>Realm</tt>s, not just one realm.</p>
 *
 * <p>This is useful in a multi-realm authentication configuration - the individual <tt>AuthenticationInfo</tt>
 * objects obtained from each realm can be {@link #merge merged} into a single instance.  This instance can then be
 * returned at the end of the authentication process, giving the impression of a single underlying
 * realm/data source.
 *
 * @since 0.9
 */
public interface MergableAuthenticationInfo extends AuthenticationInfo {

    /**
     * Merges the given {@link AuthenticationInfo} into this instance.  The specific way
     * that the merge occurs is up to the implementation, but typically it involves combining
     * the principals and credentials together in this instance.  The <code>info</code> argument should
     * not be modified in any way.
     *
     * @param info the info that should be merged into this instance.
     */
    void merge(AuthenticationInfo info);

}
