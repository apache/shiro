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
package org.apache.shiro.web.filter.authz;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;


public class HttpMethodPermissionFilterTest {

    @Test
    void testPermissionMapping() {
        // Testing the isAccessAllowed would be easier, but would need to mock out the servlet request

        HttpMethodPermissionFilter filter = new HttpMethodPermissionFilter();

        String[] permsBefore = {"foo", "bar"};

        String[] permsAfter = filter.buildPermissions(permsBefore, filter.getHttpMethodAction("get"));
        assertEquals(2, permsAfter.length);
        assertEquals("foo:read", permsAfter[0]);
        assertEquals("bar:read", permsAfter[1]);

        assertEquals("foo:read", filter.buildPermissions(permsBefore, filter.getHttpMethodAction("head"))[0]);
        assertEquals("foo:update", filter.buildPermissions(permsBefore, filter.getHttpMethodAction("put"))[0]);
        assertEquals("foo:create", filter.buildPermissions(permsBefore, filter.getHttpMethodAction("post"))[0]);
        assertEquals("foo:create", filter.buildPermissions(permsBefore, filter.getHttpMethodAction("mkcol"))[0]);
        assertEquals("foo:delete", filter.buildPermissions(permsBefore, filter.getHttpMethodAction("delete"))[0]);
        assertEquals("foo:read", filter.buildPermissions(permsBefore, filter.getHttpMethodAction("options"))[0]);
        assertEquals("foo:read", filter.buildPermissions(permsBefore, filter.getHttpMethodAction("trace"))[0]);
    }
}
