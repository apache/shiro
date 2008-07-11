JSecurity Runtime Requirements
------------------------------

All 3rd party dependencies mentioned below are accessible in two ways:
1) In the jsecurity-<version>-with-dependencies.zip distribution's lib directory
2) After downloading jsecurity-<version>.zip (no dependencies), run 'ant retrieve-dependencies'.  This will download
the dependencies to a lib directory (peer to the build.xml).


Minimal required dependencies
-------------
All JRE versions (1.3+):  JSecurity uses SLF4J version 1.5.2 for logging - it is essentially the replacement for
Jakarta Commons Logging.  You will need to include slf4j-api.jar as well as one of its bindings depending on the
logging system you want to use.  For example, slf4j-log4j12.jar if you're using Log4J 1.2, slf4j-jdk14.jar if
you're using JDK 1.4 logging, et cetera.  Bindings can be found in the public maven repository under the
org.slf4j group id or on the SLF4J website at http://www.slf4j.org.

Java 1.3 and 1.4 only:  in addition to the above logging logging jars, you will need retroweaver.jar and its
                        associated dependencies.


Feature-based dependencies
--------------------------
- If you use JSecurity's native text-based configuration (jsecurity.ini or servlet filter configuration), include
  Jakarta commons-beanutils-core.jar

- If you want to use JSecurity's enterprise session management (heterogeneous clients, SSO support, etc):
  . include ehcache.jar and backport-util-concurrent.jar
