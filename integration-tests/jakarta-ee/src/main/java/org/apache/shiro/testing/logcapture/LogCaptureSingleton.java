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
package org.apache.shiro.testing.logcapture;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.ejb.Singleton;
import javax.ejb.Startup;

/**
 * Entry point for capturing logs and exceptions via servlet
 */
@Singleton
@Startup
@SuppressWarnings("MagicNumber")
public class LogCaptureSingleton {
    @PostConstruct
    void init() {
        LogCapture.get().setupLogging(50);
    }

    @PreDestroy
    void destroy() {
        LogCapture.get().resetLogging();
    }
}
