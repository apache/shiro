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

import java.util.Deque;
import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * View server exceptions within a servlet
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class LogCapture {
    private static final LogCapture INSTANCE = new LogCapture();
    private static final Logger GLOBAL_LOGGER = Logger.getLogger("");

    private final AtomicReference<LoggingHandler> handler = new AtomicReference<>();

    public static LogCapture get() {
        return INSTANCE;
    }

    public void setupLogging(int capacity) {
        if (!handler.compareAndSet(null, new LoggingHandler(capacity))) {
            throw new IllegalStateException("Trying to turn on logging twice");
        }

        GLOBAL_LOGGER.addHandler(handler.get());
    }

    public void resetLogging() {
        handler.accumulateAndGet(null, (curr, nullv) -> {
            if (curr == null) {
                throw new IllegalStateException("Trying to turn logging off twice");
            }
            GLOBAL_LOGGER.removeHandler(curr);
            return nullv;
        });
    }

    public LogRecord poll() {
        Objects.requireNonNull(handler.get(), "Logging not set up");
        return handler.get().records.poll();
    }

    private static class LoggingHandler extends Handler {
        private final Deque<LogRecord> records;
        private final int capacity;


        LoggingHandler(int capacity) {
            records = new ConcurrentLinkedDeque<>();
            this.capacity = capacity;
        }

        @Override
        public void publish(LogRecord record) {
            // the below line is if integrating with Payara due to race condition
//            records.offer(new GFLogRecord(record));
            records.offer(record);
            if (records.size() > capacity) {
                records.poll();
            }
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() throws SecurityException {
        }
    }
}
