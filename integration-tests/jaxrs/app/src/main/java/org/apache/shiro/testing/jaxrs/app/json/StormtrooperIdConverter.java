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

package org.apache.shiro.testing.jaxrs.app.json;

import org.apache.shiro.testing.jaxrs.app.model.StormtrooperId;

import jakarta.enterprise.context.Dependent;
import jakarta.json.bind.adapter.JsonbAdapter;
import jakarta.ws.rs.ext.Provider;

@Dependent
@Provider
public class StormtrooperIdConverter implements JsonbAdapter<StormtrooperId, String> {
    @Override
    public String adaptToJson(StormtrooperId obj) {
        return obj.getValue();
    }

    @Override
    public StormtrooperId adaptFromJson(String obj) {
        return new StormtrooperId(obj);
    }
}
