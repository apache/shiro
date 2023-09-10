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

package org.apache.shiro.testing.jaxrs.app.dao;

import com.github.javafaker.Faker;
import com.github.javafaker.Name;
import com.github.javafaker.service.FakeValuesService;
import com.github.javafaker.service.RandomService;
import org.apache.shiro.testing.jaxrs.app.model.Stormtrooper;
import org.apache.shiro.testing.jaxrs.app.model.StormtrooperId;
import org.apache.shiro.testing.jaxrs.app.model.StormtrooperTemplate;

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Default;
import java.time.Instant;
import java.util.Collection;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@SuppressWarnings("checkstyle:MagicNumber")
@Dependent
@Default
public class InMemoryStormtrooperDao implements StormtrooperDao {

    private static final Map<StormtrooperId, Stormtrooper> TROOPERS = new ConcurrentHashMap<>();

    static {
        Faker faker = new Faker();
        final FakeValuesService fakeValuesService = new FakeValuesService(Locale.ENGLISH, new RandomService());
        while (TROOPERS.size() < 50) {
            final StormtrooperId stormtrooperId = new StormtrooperId(fakeValuesService.numerify("u######"));
            final Name name = faker.name();
            final Instant registeredAt = faker.date().birthday(16, 67).toInstant();
            final Stormtrooper stormtrooper = new Stormtrooper(stormtrooperId, name.firstName(), name.lastName(), registeredAt);
            TROOPERS.put(stormtrooperId, stormtrooper);
        }
    }

    @Override
    public Collection<Stormtrooper> listTroopers() {
        return TROOPERS.values();
    }

    @Override
    public Optional<Stormtrooper> getStormtrooper(StormtrooperId id) {
        return Optional.ofNullable(TROOPERS.get(id));
    }

    @Override
    public Stormtrooper addStormtrooper(StormtrooperTemplate stormtrooperTemplate) {
        final Stormtrooper stormtrooper = new Stormtrooper(StormtrooperId.createFresh(),
                stormtrooperTemplate.getFirstName(),
                stormtrooperTemplate.getLastName(),
                Instant.now());
        TROOPERS.put(stormtrooper.getStormtrooperId(), stormtrooper);

        return stormtrooper;
    }

    @Override
    public Stormtrooper updateStormtrooper(StormtrooperId id, Stormtrooper stormtrooper) {
        // make sure the user did not input a wrong ID
        Stormtrooper toBeAdded = Stormtrooper.copyOf(stormtrooper)
                .withId(id);
        TROOPERS.put(stormtrooper.getStormtrooperId(), toBeAdded);
        return toBeAdded;
    }

    @Override
    public boolean deleteStormtrooper(StormtrooperId id) {
        // TODO: implement
        throw new UnsupportedOperationException("not yet implemented: "
                + "[org.apache.shiro.testing.meecrowave.jaxrs.dao.InMemoryStormtrooperDao::deleteStormtrooper].");
    }
}
