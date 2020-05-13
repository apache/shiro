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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.DefaultParser;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.lang.codec.Base64;
import org.apache.shiro.lang.codec.Hex;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.UnknownAlgorithmException;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.crypto.hash.HashRequest;
import org.apache.shiro.crypto.hash.SimpleHashRequest;
import org.apache.shiro.crypto.hash.format.DefaultHashFormatFactory;
import org.apache.shiro.crypto.hash.format.HashFormat;
import org.apache.shiro.crypto.hash.format.HashFormatFactory;
import org.apache.shiro.crypto.hash.format.HexFormat;
import org.apache.shiro.crypto.hash.format.Shiro1CryptFormat;
import org.apache.shiro.lang.io.ResourceUtils;
import org.apache.shiro.lang.util.ByteSource;
import org.apache.shiro.lang.util.StringUtils;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

/**
 * Commandline line utility to hash data such as strings, passwords, resources (files, urls, etc).
 * <p/>
 * Usage:
 * <pre>
 * java -jar shiro-tools-hasher<em>-version</em>-cli.jar
 * </pre>
 * This will print out all supported options with documentation.
 *
 * @since 1.2
 */
public final class Hasher {

    private static final String HEX_PREFIX = "0x";
    private static final String DEFAULT_ALGORITHM_NAME = "MD5";
    private static final String DEFAULT_PASSWORD_ALGORITHM_NAME = DefaultPasswordService.DEFAULT_HASH_ALGORITHM;
    private static final int DEFAULT_GENERATED_SALT_SIZE = 128;
    private static final int DEFAULT_NUM_ITERATIONS = 1;
    private static final int DEFAULT_PASSWORD_NUM_ITERATIONS = DefaultPasswordService.DEFAULT_HASH_ITERATIONS;

    private static final Option ALGORITHM = new Option("a", "algorithm", true, "hash algorithm name.  Defaults to SHA-256 when password hashing, MD5 otherwise.");
    private static final Option DEBUG = new Option("d", "debug", false, "show additional error (stack trace) information.");
    private static final Option FORMAT = new Option("f", "format", true, "hash output format.  Defaults to 'shiro1' when password hashing, 'hex' otherwise.  See below for more information.");
    private static final Option HELP = new Option("help", "help", false, "show this help message.");
    private static final Option ITERATIONS = new Option("i", "iterations", true, "number of hash iterations.  Defaults to " + DEFAULT_PASSWORD_NUM_ITERATIONS + " when password hashing, 1 otherwise.");
    private static final Option PASSWORD = new Option("p", "password", false, "hash a password (disable typing echo)");
    private static final Option PASSWORD_NC = new Option("pnc", "pnoconfirm", false, "hash a password (disable typing echo) but disable password confirmation prompt.");
    private static final Option RESOURCE = new Option("r", "resource", false, "read and hash the resource located at <value>.  See below for more information.");
    private static final Option SALT = new Option("s", "salt", true, "use the specified salt.  <arg> is plaintext.");
    private static final Option SALT_BYTES = new Option("sb", "saltbytes", true, "use the specified salt bytes.  <arg> is hex or base64 encoded text.");
    private static final Option SALT_GEN = new Option("gs", "gensalt", false, "generate and use a random salt. Defaults to true when password hashing, false otherwise.");
    private static final Option NO_SALT_GEN = new Option("ngs", "nogensalt", false, "do NOT generate and use a random salt (valid during password hashing).");
    private static final Option SALT_GEN_SIZE = new Option("gss", "gensaltsize", true, "the number of salt bits (not bytes!) to generate.  Defaults to 128.");
    private static final Option PRIVATE_SALT = new Option("ps", "privatesalt", true, "use the specified private salt.  <arg> is plaintext.");
    private static final Option PRIVATE_SALT_BYTES = new Option("psb", "privatesaltbytes", true, "use the specified private salt bytes.  <arg> is hex or base64 encoded text.");

    private static final String SALT_MUTEX_MSG = createMutexMessage(SALT, SALT_BYTES);

    private static final HashFormatFactory HASH_FORMAT_FACTORY = new DefaultHashFormatFactory();

    static {
        ALGORITHM.setArgName("name");
        SALT_GEN_SIZE.setArgName("numBits");
        ITERATIONS.setArgName("num");
        SALT.setArgName("sval");
        SALT_BYTES.setArgName("encTxt");
    }

    public static void main(String[] args) {

        CommandLineParser parser = new DefaultParser();

        Options options = new Options();
        options.addOption(HELP).addOption(DEBUG).addOption(ALGORITHM).addOption(ITERATIONS);
        options.addOption(RESOURCE).addOption(PASSWORD).addOption(PASSWORD_NC);
        options.addOption(SALT).addOption(SALT_BYTES).addOption(SALT_GEN).addOption(SALT_GEN_SIZE).addOption(NO_SALT_GEN);
        options.addOption(PRIVATE_SALT).addOption(PRIVATE_SALT_BYTES);
        options.addOption(FORMAT);

        boolean debug = false;
        String algorithm = null; //user unspecified
        int iterations = 0; //0 means unspecified by the end-user
        boolean resource = false;
        boolean password = false;
        boolean passwordConfirm = true;
        String saltString = null;
        String saltBytesString = null;
        boolean generateSalt = false;
        int generatedSaltSize = DEFAULT_GENERATED_SALT_SIZE;
        String privateSaltString = null;
        String privateSaltBytesString = null;

        String formatString = null;

        char[] passwordChars = null;

        try {
            CommandLine line = parser.parse(options, args);

            if (line.hasOption(HELP.getOpt())) {
                printHelpAndExit(options, null, debug, 0);
            }
            if (line.hasOption(DEBUG.getOpt())) {
                debug = true;
            }
            if (line.hasOption(ALGORITHM.getOpt())) {
                algorithm = line.getOptionValue(ALGORITHM.getOpt());
            }
            if (line.hasOption(ITERATIONS.getOpt())) {
                iterations = getRequiredPositiveInt(line, ITERATIONS);
            }
            if (line.hasOption(PASSWORD.getOpt())) {
                password = true;
                generateSalt = true;
            }
            if (line.hasOption(RESOURCE.getOpt())) {
                resource = true;
            }
            if (line.hasOption(PASSWORD_NC.getOpt())) {
                password = true;
                generateSalt = true;
                passwordConfirm = false;
            }
            if (line.hasOption(SALT.getOpt())) {
                saltString = line.getOptionValue(SALT.getOpt());
            }
            if (line.hasOption(SALT_BYTES.getOpt())) {
                saltBytesString = line.getOptionValue(SALT_BYTES.getOpt());
            }
            if (line.hasOption(NO_SALT_GEN.getOpt())) {
                generateSalt = false;
            }
            if (line.hasOption(SALT_GEN.getOpt())) {
                generateSalt = true;
            }
            if (line.hasOption(SALT_GEN_SIZE.getOpt())) {
                generateSalt = true;
                generatedSaltSize = getRequiredPositiveInt(line, SALT_GEN_SIZE);
                if (generatedSaltSize % 8 != 0) {
                    throw new IllegalArgumentException("Generated salt size must be a multiple of 8 (e.g. 128, 192, 256, 512, etc).");
                }
            }
            if (line.hasOption(PRIVATE_SALT.getOpt())) {
                privateSaltString = line.getOptionValue(PRIVATE_SALT.getOpt());
            }
            if (line.hasOption(PRIVATE_SALT_BYTES.getOpt())) {
                privateSaltBytesString = line.getOptionValue(PRIVATE_SALT_BYTES.getOpt());
            }
            if (line.hasOption(FORMAT.getOpt())) {
                formatString = line.getOptionValue(FORMAT.getOpt());
            }

            String sourceValue;

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
                sourceValue = toString(remainingArgs);

                if (resource) {
                    if (!ResourceUtils.hasResourcePrefix(sourceValue)) {
                        source = toFile(sourceValue);
                    } else {
                        source = ResourceUtils.getInputStreamForPath(sourceValue);
                    }
                } else {
                    source = sourceValue;
                }
            }

            if (algorithm == null) {
                if (password) {
                    algorithm = DEFAULT_PASSWORD_ALGORITHM_NAME;
                } else {
                    algorithm = DEFAULT_ALGORITHM_NAME;
                }
            }

            if (iterations < DEFAULT_NUM_ITERATIONS) {
                //Iterations were not specified.  Default to 350,000 when password hashing, and 1 for everything else:
                if (password) {
                    iterations = DEFAULT_PASSWORD_NUM_ITERATIONS;
                } else {
                    iterations = DEFAULT_NUM_ITERATIONS;
                }
            }

            ByteSource publicSalt = getSalt(saltString, saltBytesString, generateSalt, generatedSaltSize);
            ByteSource privateSalt = getSalt(privateSaltString, privateSaltBytesString, false, generatedSaltSize);
            HashRequest hashRequest = new SimpleHashRequest(algorithm, ByteSource.Util.bytes(source), publicSalt, iterations);

            DefaultHashService hashService = new DefaultHashService();
            hashService.setPrivateSalt(privateSalt);
            Hash hash = hashService.computeHash(hashRequest);

            if (formatString == null) {
                //Output format was not specified.  Default to 'shiro1' when password hashing, and 'hex' for
                //everything else:
                if (password) {
                    formatString = Shiro1CryptFormat.class.getName();
                } else {
                    formatString = HexFormat.class.getName();
                }
            }

            HashFormat format = HASH_FORMAT_FACTORY.getInstance(formatString);

            if (format == null) {
                throw new IllegalArgumentException("Unrecognized hash format '" + formatString + "'.");
            }

            String output = format.format(hash);

            System.out.println(output);

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

    private static String createMutexMessage(Option... options) {
        StringBuilder sb = new StringBuilder();
        sb.append("The ");

        for (int i = 0; i < options.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            Option o = options[0];
            sb.append("-").append(o.getOpt()).append("/--").append(o.getLongOpt());
        }
        sb.append(" and generated salt options are mutually exclusive.  Only one of them may be used at a time");
        return sb.toString();
    }

    private static void exit(Exception e, boolean debug) {
        printException(e, debug);
        System.exit(-1);
    }

    private static int getRequiredPositiveInt(CommandLine line, Option option) {
        String iterVal = line.getOptionValue(option.getOpt());
        try {
            return Integer.parseInt(iterVal);
        } catch (NumberFormatException e) {
            String msg = "'" + option.getLongOpt() + "' value must be a positive integer.";
            throw new IllegalArgumentException(msg, e);
        }
    }

    private static ByteSource getSalt(String saltString, String saltBytesString, boolean generateSalt, int generatedSaltSize) {

        if (saltString != null) {
            if (generateSalt || (saltBytesString != null)) {
                throw new IllegalArgumentException(SALT_MUTEX_MSG);
            }
            return ByteSource.Util.bytes(saltString);
        }

        if (saltBytesString != null) {
            if (generateSalt) {
                throw new IllegalArgumentException(SALT_MUTEX_MSG);
            }

            String value = saltBytesString;
            boolean base64 = true;
            if (saltBytesString.startsWith(HEX_PREFIX)) {
                //hex:
                base64 = false;
                value = value.substring(HEX_PREFIX.length());
            }
            byte[] bytes;
            if (base64) {
                bytes = Base64.decode(value);
            } else {
                bytes = Hex.decode(value);
            }
            return ByteSource.Util.bytes(bytes);
        }

        if (generateSalt) {
            SecureRandomNumberGenerator generator = new SecureRandomNumberGenerator();
            int byteSize = generatedSaltSize / 8; //generatedSaltSize is in *bits* - convert to byte size:
            return generator.nextBytes(byteSize);
        }

        //no salt used:
        return null;
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

    private static void printHelp(Options options, Exception e, boolean debug) {
        HelpFormatter help = new HelpFormatter();
        String command = "java -jar shiro-tools-hasher-<version>.jar [options] [<value>]";
        String header = "\nPrint a cryptographic hash (aka message digest) of the specified <value>.\n--\nOptions:";
        String footer = "\n" +
                "<value> is optional only when hashing passwords (see below).  It is\n" +
                "required all other times." +
                "\n\n" +
                "Password Hashing:\n" +
                "---------------------------------\n" +
                "Specify the -p/--password option and DO NOT enter a <value>.  You will\n" +
                "be prompted for a password and characters will not echo as you type." +
                "\n\n" +
                "Salting:\n" +
                "---------------------------------\n" +
                "Specifying a salt:" +
                "\n\n" +
                "You may specify a salt using the -s/--salt option followed by the salt\n" +
                "value.  If the salt value is a base64 or hex string representing a\n" +
                "byte array, you must specify the -sb/--saltbytes option to indicate this,\n" +
                "otherwise the text value bytes will be used directly." +
                "\n\n" +
                "When using -sb/--saltbytes, the -s/--salt value is expected to be a\n" +
                "base64-encoded string by default.  If the value is a hex-encoded string,\n" +
                "you must prefix the string with 0x (zero x) to indicate a hex value." +
                "\n\n" +
                "Generating a salt:" +
                "\n\n" +
                "Use the -gs/--gensalt option if you don't want to specify a salt,\n" +
                "but want a strong random salt to be generated and used during hashing.\n" +
                "The generated salt size defaults to 128 bits.  You may specify\n" +
                "a different size by using the -gss/--gensaltsize option followed by\n" +
                "a positive integer (size is in bits, not bytes)." +
                "\n\n" +
                "Because a salt must be specified if computing the hash later,\n" +
                "generated salts are only useful with the shiro1 output format;\n" +
                "the other formats do not include the generated salt." +
                "\n\n" +
                "Specifying a private salt:" +
                "\n\n" +
                "You may specify a private salt using the -ps/--privatesalt option followed\n" +
                "by the private salt value.  If the private salt value is a base64 or hex \n" +
                "string representing a byte array, you must specify the -psb/--privatesaltbytes\n" +
                "option to indicate this, otherwise the text value bytes will be used directly." +
                "\n\n" +
                "When using -psb/--privatesaltbytes, the -ps/--privatesalt value is expected to\n" +
                "be a base64-encoded string by default.  If the value is a hex-encoded string,\n" +
                "you must prefix the string with 0x (zero x) to indicate a hex value." +
                "\n\n" +
                "Files, URLs and classpath resources:\n" +
                "---------------------------------\n" +
                "If using the -r/--resource option, the <value> represents a resource path.\n" +
                "By default this is expected to be a file path, but you may specify\n" +
                "classpath or URL resources by using the classpath: or url: prefix\n" +
                "respectively." +
                "\n\n" +
                "Some examples:" +
                "\n\n" +
                "<command> -r fileInCurrentDirectory.txt\n" +
                "<command> -r ../../relativePathFile.xml\n" +
                "<command> -r ~/documents/myfile.pdf\n" +
                "<command> -r /usr/local/logs/absolutePathFile.log\n" +
                "<command> -r url:http://foo.com/page.html\n" +
                "<command> -r classpath:/WEB-INF/lib/something.jar" +
                "\n\n" +
                "Output Format:\n" +
                "---------------------------------\n" +
                "Specify the -f/--format option followed by either 1) the format ID (as defined\n" +
                "by the " + DefaultHashFormatFactory.class.getName() + "\n" +
                "JavaDoc) or 2) the fully qualified " + HashFormat.class.getName() + "\n" +
                "implementation class name to instantiate and use for formatting.\n\n" +
                "The default output format is 'shiro1' which is a Modular Crypt Format (MCF)\n" +
                "that shows all relevant information as a dollar-sign ($) delimited string.\n" +
                "This format is ideal for use in Shiro's text-based user configuration (e.g.\n" +
                "shiro.ini or a properties file).";

        printException(e, debug);

        System.out.println();
        help.printHelp(command, header, options, null);
        System.out.println(footer);
    }

    private static void printHelpAndExit(Options options, Exception e, boolean debug, int exitCode) {
        printHelp(options, e, debug);
        System.exit(exitCode);
    }

    private static char[] readPassword(boolean confirm) {
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

    private static File toFile(String path) {
        String resolved = path;
        if (path.startsWith("~/") || path.startsWith(("~\\"))) {
            resolved = path.replaceFirst("\\~", System.getProperty("user.home"));
        }
        return new File(resolved);
    }

    private static String toString(String[] strings) {
        int len = strings != null ? strings.length : 0;
        if (len == 0) {
            return null;
        }
        return StringUtils.toDelimitedString(strings, " ");
    }
}
