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

import static org.apache.shiro.testing.jakarta.ee.StatisticsResource.increment;
import java.io.Serializable;
import java.util.concurrent.atomic.AtomicInteger;
import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.enterprise.context.SessionScoped;
import javax.inject.Named;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authz.annotation.RequiresUser;

/**
 * Session-scoped Shiro-protected beans
 */
@SessionScoped
@Named
@RequiresUser
@Slf4j
public class ProtectedSessionScopedBean implements Serializable {
    private static final long serialVersionUID = 1L;

    private static final AtomicInteger INSTANCE_COUNT = new AtomicInteger();
    private final int count = INSTANCE_COUNT.incrementAndGet();

    @PostConstruct
    void postConstruct() {
        increment("pc_ss");
    }

    @PreDestroy
    void preDestroy() {
        increment("pd_ss");
    }

    public String hello() {
        return String.format("Hello from SessionScoped %s", count);
    }
}
