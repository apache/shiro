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
package org.apache.shiro.aspectj;

import org.apache.shiro.authz.annotation.PermissionParam;
import org.apache.shiro.authz.annotation.RequiresPermissions;

public class TemplatedDummyService {

    @RequiresPermissions("{name}:foo")
    public void retrieve(final @PermissionParam("name") String name) {
        // we don't care about the body
    }


    @RequiresPermissions("{param.name}:foo")
    public void retrieve(final @PermissionParam("param") Param param) {
        // we don't care about the body
    }

    public static class Param {
        private String _name;

        public Param(final String _name) {
            this._name = _name;
        }

        public String getName() {
            return _name;
        }
    }
}
