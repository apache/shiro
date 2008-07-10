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
package org.jsecurity.logging;

import java.util.regex.Pattern;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class FormattedLog implements Log {

    private static final Pattern TOKEN_PATTERN = Pattern.compile("\\{\\}");
    private String name;

    public FormattedLog() {
    }

    public FormattedLog(String name) {
        setName(name);
    }

    public String getName() {
        return this.name;
    }

    protected void setName(String name) {
        this.name = name;
    }

    protected String format(String msg, Object... args) {
        if (args != null && args.length > 0) {
            for (Object o : args) {
                msg = TOKEN_PATTERN.matcher(msg).replaceFirst(o.toString());
            }
            return msg;
        } else {
            return msg;
        }
    }

    public void trace(String msg) {
        if (isTraceEnabled()) {
            doTrace(msg);
        }
    }

    public void trace(String format, Object arg) {
        if (isTraceEnabled()) {
            doTrace(format(format, arg));
        }
    }

    public void trace(String format, Object... args) {
        if (isTraceEnabled()) {
            doTrace(format(format, args));
        }
    }

    protected abstract void doTrace(String msg);

    public void debug(String msg) {
        if (isDebugEnabled()) {
            doDebug(msg);
        }
    }

    public void debug(String format, Object arg) {
        if (isDebugEnabled()) {
            doDebug(format(format, arg));
        }
    }

    public void debug(String format, Object... args) {
        if (isDebugEnabled()) {
            debug(format(format, args));
        }
    }

    protected abstract void doDebug(String msg);

    public void info(String msg) {
        if (isInfoEnabled()) {
            doInfo(msg);
        }
    }

    public void info(String format, Object arg) {
        if (isInfoEnabled()) {
            doInfo(format(format, arg));
        }
    }

    public void info(String format, Object... args) {
        if (isInfoEnabled()) {
            doInfo(format(format, args));
        }
    }

    protected abstract void doInfo(String msg);

    public void warn(String msg) {
        if (isWarnEnabled()) {
            doWarn(msg);
        }
    }

    public void warn(String format, Object arg) {
        if (isWarnEnabled()) {
            doWarn(format(format, arg));
        }
    }

    public void warn(String format, Object... args) {
        if (isWarnEnabled()) {
            doWarn(format(format, args));
        }
    }

    protected abstract void doWarn(String msg);

    public void error(String msg) {
        if (isErrorEnabled()) {
            doError(msg);
        }
    }

    public void error(String format, Object arg) {
        if (isErrorEnabled()) {
            doError(format(format, arg));
        }
    }

    public void error(String format, Object... args) {
        if (isErrorEnabled()) {
            doError(format(format, args));
        }
    }

    protected abstract void doError(String msg);
}
