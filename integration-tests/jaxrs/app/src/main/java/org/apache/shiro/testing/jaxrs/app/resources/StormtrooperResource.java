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

package org.apache.shiro.testing.jaxrs.app.resources;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.testing.jaxrs.app.dao.StormtrooperDao;
import org.apache.shiro.testing.jaxrs.app.model.Stormtrooper;
import org.apache.shiro.testing.jaxrs.app.model.StormtrooperId;
import org.apache.shiro.testing.jaxrs.app.model.StormtrooperTemplate;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Default;
import javax.inject.Inject;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import java.util.Collection;
import java.util.Optional;

@ApplicationScoped
@Default
@RequiresUser
@Path("/troopers")
@Produces("application/json")
public class StormtrooperResource {

    @Inject
    private StormtrooperDao trooperDao;

    public StormtrooperResource() {
    }

    public StormtrooperResource(StormtrooperDao trooperDao) {
        this.trooperDao = trooperDao;
    }

    @GET
    @RequiresPermissions("user:read")
    public Collection<Stormtrooper> listTroopers() {
        return trooperDao.listTroopers();
    }


    @Path("/{id}")
    @GET
    @RequiresPermissions("troopers:read")
    public Stormtrooper getTrooper(@PathParam("id") StormtrooperId id) throws NotFoundException {
        Optional<Stormtrooper> stormtrooper = trooperDao.getStormtrooper(id);

        return stormtrooper.orElseThrow(NotFoundException::new);
    }

    @POST
    @RequiresPermissions("troopers:create")
    public Stormtrooper createTrooper(StormtrooperTemplate trooperTemplate) {

        return trooperDao.addStormtrooper(trooperTemplate);
    }

    @Path("/{id}")
    @POST
    @RequiresPermissions("troopers:update")
    public Stormtrooper updateTrooper(@PathParam("id") StormtrooperId id, Stormtrooper updatedTrooper) throws NotFoundException {

        return trooperDao.updateStormtrooper(id, updatedTrooper);
    }

    @Path("/{id}")
    @DELETE
    @RequiresPermissions("troopers:delete")
    public void deleteTrooper(@PathParam("id") StormtrooperId id) {
        trooperDao.deleteStormtrooper(id);
    }

    public StormtrooperDao getTrooperDao() {
        return trooperDao;
    }

    public void setTrooperDao(StormtrooperDao trooperDao) {
        this.trooperDao = trooperDao;
    }
}
