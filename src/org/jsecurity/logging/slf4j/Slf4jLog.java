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
package org.jsecurity.logging.slf4j;

import org.jsecurity.logging.Log;
import org.slf4j.Logger;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class Slf4jLog implements Log {

    protected Logger log;

    public Slf4jLog(Logger log) {
        this.log = log;
    }

    public String getName() {
        return log.getName();
    }

    public boolean isTraceEnabled() {
        return log.isTraceEnabled();
    }

    public void trace(String msg) {
        log.trace(msg);
    }

    public void trace(String format, Object arg) {
        log.trace(format, arg);
    }

    public void trace(String format, Object... args) {
        log.trace(format, args);
    }

    public void trace(String msg, Throwable t) {
        log.trace(msg, t);
    }

    public boolean isDebugEnabled() {
        return log.isDebugEnabled();
    }

    public void debug(String msg) {
        log.debug(msg);
    }

    public void debug(String format, Object arg) {
        log.debug(format);
    }

    public void debug(String format, Object... args) {
        log.debug(format, args);
    }

    public void debug(String msg, Throwable t) {
        log.debug(msg, t);
    }

    public boolean isInfoEnabled() {
        return log.isInfoEnabled();
    }

    public void info(String msg) {
        log.info(msg);
    }

    public void info(String format, Object arg) {
        log.info(format, arg);
    }

    public void info(String format, Object... args) {
        log.info(format, args);
    }

    public void info(String msg, Throwable t) {
        log.info(msg, t);
    }

    public boolean isWarnEnabled() {
        return log.isWarnEnabled();
    }

    public void warn(String msg) {
        log.warn(msg);
    }

    public void warn(String format, Object arg) {
        log.warn(format, arg);
    }

    public void warn(String format, Object... args) {
        log.warn(format, args);
    }

    public void warn(String msg, Throwable t) {
        log.warn(msg, t);
    }

    public boolean isErrorEnabled() {
        return log.isErrorEnabled();
    }

    public void error(String msg) {
        log.error(msg);
    }

    public void error(String format, Object arg) {
        log.error(format, arg);
    }

    public void error(String format, Object... args) {
        log.error(format, args);
    }

    public void error(String msg, Throwable t) {
        log.error(msg, t);
    }
}
