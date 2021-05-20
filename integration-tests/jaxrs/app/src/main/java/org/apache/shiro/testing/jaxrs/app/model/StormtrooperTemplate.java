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

package org.apache.shiro.testing.jaxrs.app.model;

import javax.json.bind.annotation.JsonbCreator;
import javax.json.bind.annotation.JsonbProperty;

import static java.util.Objects.requireNonNull;

/**
 * Template for add operation without ID.
 *
 * <p>The user cannot supply an ID for POST (add),
 * unless specified through PUT operation.</p>
 */
public class StormtrooperTemplate {

    private final String firstName;

    private final String lastName;


    @JsonbCreator
    public StormtrooperTemplate(@JsonbProperty("first_name") String firstName,
                                @JsonbProperty("last_name") String lastName) {
        this.firstName = requireNonNull(firstName);
        this.lastName = requireNonNull(lastName);
    }

    public static StormtrooperTemplate copyOf(StormtrooperTemplate stormtrooper) {
        return new StormtrooperTemplate(
                stormtrooper.firstName,
                stormtrooper.lastName
        );
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

}
