/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.testing.jakarta.ee;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import lombok.AccessLevel;
import lombok.Getter;

/**
 * returns statistics about beans
 */
@Path("statistics")
public class StatisticsResource {
    @Getter(AccessLevel.PACKAGE)
    @SuppressWarnings("ConstantName")
    private static final Map<String, AtomicInteger> statistics = new ConcurrentHashMap<>();

    public static void increment(String which) {
        statistics.compute(which, (k, v) -> {
            if (v == null) {
                return new AtomicInteger(1);
            } else {
                v.incrementAndGet();
                return v;
            }
        });
    }

    @GET
    @Path("{which}")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getStatistic(@PathParam("which") String which) {
        return Response.ok(statistics.getOrDefault(which, new AtomicInteger(0)).get()).build();
    }

    @GET
    @Path("clear")
    @Produces(MediaType.TEXT_PLAIN)
    public Response clear() {
        statistics.clear();
        return Response.ok().build();
    }
}
