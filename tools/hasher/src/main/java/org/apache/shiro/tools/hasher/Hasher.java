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
package org.apache.shiro.tools.hasher;

import org.apache.commons.cli.*;
import org.apache.shiro.crypto.UnknownAlgorithmException;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.io.ResourceUtils;
import org.apache.shiro.util.JavaEnvironment;
import org.apache.shiro.util.StringUtils;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

/**
 * Commandline line utility to hash data such as strings, passwords, resources (files, urls, etc).
 * <p/>
 * Usage:
 * <pre>
 * java -jar shiro-tools-hasher<em>-version</em>.jar
 * </pre>
 * This will print out all supported options with documentation.
 *
 * @since 1.2
 */
public final class Hasher {


    private static final String DEFAULT_ALGORITHM_NAME = "MD5";
    private static final int DEFAULT_NUM_ITERATIONS = 1;

    private static final String ALG_OPT = "a";
    private static final String ALG_OPT_LONG = "algorithm";
    private static final String DEBUG_OPT = "d";
    private static final String DEBUG_OPT_LONG = "debug"; //show stack traces if there are any.
    private static final String ITER_OPT = "i";
    private static final String ITER_OPT_LONG = "iterations";
    private static final String HEX_OPT = "h";
    private static final String HEX_OPT_LONG = "hex";
    private static final String HELP_OPT = "help";
    private static final String HELP_OPT_LONG = "help";
    private static final String PASSWORD_OPT = "p";
    private static final String PASSWORD_OPT_LONG = "password";
    private static final String PASSWORD_OPT_NOCONFIRM = "pnc";
    private static final String PASSWORD_OPT_NOCONFIRM_LONG = "pnoconfirm";
    private static final String RESOURCE_OPT = "r";
    private static final String RESOURCE_OPT_LONG = "resource";


    public static void main(String[] args) {

        CommandLineParser parser = new PosixParser();

        Options options = new Options();
        options.addOption(ALG_OPT, ALG_OPT_LONG, true, "hash algorithm name.  Defaults to MD5.");
        options.addOption(ITER_OPT, ITER_OPT_LONG, true, "number of hash iterations.  Defaults to 1.");
        options.addOption(HEX_OPT, HEX_OPT_LONG, false, "print hex value.  Defaults to Base64.");
        options.addOption(HELP_OPT, HELP_OPT_LONG, false, "print this help message.");
        options.addOption(DEBUG_OPT, DEBUG_OPT_LONG, false, "show additional error (stack trace) information.");
        options.addOption(PASSWORD_OPT, PASSWORD_OPT_LONG, false, "hash a password (do not echo).");
        options.addOption(RESOURCE_OPT, RESOURCE_OPT_LONG, false, "read and hash the resource located at <value>. See below for more information.");
        options.addOption(PASSWORD_OPT_NOCONFIRM, PASSWORD_OPT_NOCONFIRM_LONG, false, "disable confirmation prompt for password hashing.");

        boolean debug = false;
        String algorithm = DEFAULT_ALGORITHM_NAME;
        int iterations = DEFAULT_NUM_ITERATIONS;
        boolean base64 = true;
        boolean resource = false;
        boolean password = false;
        boolean passwordConfirm = true;

        char[] passwordChars = null;

        try {
            CommandLine line = parser.parse(options, args);

            if (line.hasOption(HELP_OPT)) {
                printHelpAndExit(options, null, debug, 0);
            }
            if (line.hasOption(DEBUG_OPT)) {
                debug = true;
            }
            if (line.hasOption(ALG_OPT)) {
                algorithm = line.getOptionValue(ALG_OPT);
            }
            if (line.hasOption(ITER_OPT)) {
                iterations = getRequiredPositiveInt(line, ITER_OPT, ITER_OPT_LONG);
            }
            if (line.hasOption(HEX_OPT)) {
                base64 = false;
            }
            if (line.hasOption(PASSWORD_OPT)) {
                password = true;
            }
            if (line.hasOption(RESOURCE_OPT)) {
                resource = true;
            }
            if (line.hasOption(PASSWORD_OPT_NOCONFIRM)) {
                passwordConfirm = false;
            }

            Object source;

            if (password) {
                passwordChars = readPassword(passwordConfirm);
                source = passwordChars;
            } else {
                String[] remainingArgs = line.getArgs();
                if (remainingArgs == null || remainingArgs.length != 1) {
                    printHelpAndExit(options, null, debug, -1);
                }

                assert remainingArgs != null;
                String value = toString(remainingArgs);

                if (resource) {
                    if (!ResourceUtils.hasResourcePrefix(value)) {
                        source = toFile(value);
                    } else {
                        source = ResourceUtils.getInputStreamForPath(value);
                    }
                } else {
                    source = value;
                }
            }

            SimpleHash hash = new SimpleHash(algorithm, source, /* salt not supported yet*/ null, iterations);
            if (base64) {
                System.out.println(hash.toBase64());
            } else {
                System.out.println(hash.toHex());
            }
        } catch (IllegalArgumentException iae) {
            exit(iae, debug);
        } catch (UnknownAlgorithmException uae) {
            exit(uae, debug);
        } catch (IOException ioe) {
            exit(ioe, debug);
        } catch (Exception e) {
            printHelpAndExit(options, e, debug, -1);
        } finally {
            if (passwordChars != null && passwordChars.length > 0) {
                for (int i = 0; i < passwordChars.length; i++) {
                    passwordChars[i] = ' ';
                }
            }
        }
    }

    private static String toString(String[] strings) {
        int len = strings != null ? strings.length : 0;
        if (len == 0) {
            return null;
        }
        return StringUtils.toDelimitedString(strings, " ");
    }

    private static int getRequiredPositiveInt(CommandLine line, String opt, String optLong) {
        String iterVal = line.getOptionValue(opt);
        try {
            return Integer.parseInt(iterVal);
        } catch (NumberFormatException e) {
            String msg = "'" + optLong + "' value must be a positive integer.";
            throw new IllegalArgumentException(msg, e);
        }
    }

    private static File toFile(String path) {
        String resolved = path;
        if (path.startsWith("~/") || path.startsWith(("~\\"))) {
            resolved = path.replaceFirst("\\~", System.getProperty("user.home"));
        }
        return new File(resolved);
    }

    private static char[] readPassword(boolean confirm) {
        if (!JavaEnvironment.isAtLeastVersion16()) {
            String msg = "Password hashing (prompt without echo) uses the java.io.Console to read passwords " +
                    "safely.  This is only available on Java 1.6 platforms and later.";
            throw new IllegalArgumentException(msg);
        }
        java.io.Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("java.io.Console is not available on the current JVM.  Cannot read passwords.");
        }
        char[] first = console.readPassword("%s", "Password to hash: ");
        if (first == null || first.length == 0) {
            throw new IllegalArgumentException("No password specified.");
        }
        if (confirm) {
            char[] second = console.readPassword("%s", "Password to hash (confirm): ");
            if (!Arrays.equals(first, second)) {
                String msg = "Password entries do not match.";
                throw new IllegalArgumentException(msg);
            }
        }
        return first;
    }

    private static void printHelp(Options options, Exception e, boolean debug) {
        HelpFormatter help = new HelpFormatter();
        String command = "java -jar shiro-tools-hasher-<version>.jar [options] [<value>]";
        String header = "\nPrint a cryptographic hash (aka message digest) of the specified <value>.\n--\nOptions:";
        String footer = "\n" +
                "<value> is optional only when hashing passwords (see below).  It is\n" +
                "required all other times.\n\n" +
                "Password Hashing:\n--\n" +
                "Specify the -p/--password option and DO NOT enter a <value>.  You will\n" +
                "be prompted for a password and characters will not echo as you type.\n\n" +
                "Files, URLs and classpath resources:\n--\n" +
                "If using the -r/--resource option, the <value> represents a resource path.\n" +
                "By default this is expected to be a file path, but you may specify\n" +
                "classpath or URL resources by using the classpath: or url: prefix\n" +
                "respectively.\n\n" +
                "Some examples:\n\n" +
                "<command> -r fileInCurrentDirectory.txt\n" +
                "<command> -r ../../relativePathFile.xml\n" +
                "<command> -r ~/documents/myfile.pdf\n"+
                "<command> -r /usr/local/logs/absolutePathFile.log\n" +
                "<command> -r url:http://foo.com/page.html\n" +
                "<command> -r classpath:/WEB-INF/lib/something.jar";

        printException(e, debug);

        System.out.println();
        help.printHelp(command, header, options, null);
        System.out.println(footer);
    }

    private static void exit(Exception e, boolean debug) {
        printException(e, debug);
        System.exit(-1);
    }

    private static void printException(Exception e, boolean debug) {
        if (e != null) {
            System.out.println();
            if (debug) {
                System.out.println("Error: ");
                e.printStackTrace(System.out);
                System.out.println(e.getMessage());

            } else {
                System.out.println("Error: " + e.getMessage());
                System.out.println();
                System.out.println("Specify -d or --debug for more information.");
            }
        }
    }

    private static void printHelpAndExit(Options options, Exception e, boolean debug, int exitCode) {
        printHelp(options, e, debug);
        System.exit(exitCode);
    }
}
