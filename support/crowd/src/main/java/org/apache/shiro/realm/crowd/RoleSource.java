/**
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.realm.crowd;

/**
 * The Atlassian Crowd server as the concept of role and group memberships.
 * Both of which can be can be mapped to Shiro roles.  This realm
 * implementation allows the deployer to select either or both memberships to
 * map to Shiro roles.
 * <p/>
 * These enums are use to direct the Shiro realm where to obtain roles.
 * Either or both of the enums may be used.
 *
 * @version $Rev$ $Date$
 */
public enum RoleSource {

    /**
     * Obtain Shiro roles from Crowd group memberships
     */
    ROLES_FROM_CROWD_GROUPS,

    /**
     * Obtain Shiro roles from Crowd role memberships
     */
    ROLES_FROM_CROWD_ROLES
}
