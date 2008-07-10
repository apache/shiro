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
package org.jsecurity.logging.console;

import org.jsecurity.logging.FormattedLog;

/**
 * Simple implementation that always prints to <code>System.out</code>
 *
 * <p>This implementation does not support log levels therefore <em>all</em> messages are printed out always.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class ConsoleLog extends FormattedLog {

    private static final String name = "ConsoleLog";

    public ConsoleLog() {
    }

    public String getName() {
        return name;
    }

    public boolean isTraceEnabled() {
        return true;
    }

    public boolean isDebugEnabled() {
        return true;
    }

    public boolean isInfoEnabled() {
        return true;
    }

    public boolean isWarnEnabled() {
        return true;
    }

    public boolean isErrorEnabled() {
        return true;
    }

    protected void out(String msg) {
        System.out.println(msg);
    }

    protected void doTrace(String msg) {
        out(msg);
    }

    protected void doDebug(String msg) {
        out(msg);
    }

    protected void doInfo(String msg) {
        out(msg);
    }

    protected void doWarn(String msg) {
        out(msg);
    }

    protected void doError(String msg) {
        out(msg);
    }

    protected void tout(String msg, Throwable t) {
        out(msg);
        t.printStackTrace(System.out);
    }

    public void trace(String msg, Throwable t) {
        tout(msg, t);
    }

    public void debug(String msg, Throwable t) {
        tout(msg, t);
    }

    public void info(String msg, Throwable t) {
        tout(msg, t);
    }

    public void warn(String msg, Throwable t) {
        tout(msg, t);
    }

    public void error(String msg, Throwable t) {
        tout(msg, t);
    }
}
