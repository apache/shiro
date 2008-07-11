JSecurity Runtime Requirements
------------------------------

All 3rd party dependencies mentioned below are accessible in two ways:
1) In the jsecurity-<version>-with-dependencies.zip distribution's lib directory
2) After downloading jsecurity-<version>.zip (no dependencies), run 'ant retrieve-dependencies'.  This will download
the dependencies to a lib directory (peer to the build.xml).


Minimal required dependencies
-------------
Java 1.5 and later: Ensure jsecurity.jar, slf4j-api.jar and one if its bindings (slf4j-log4j12.jar, slf4j-jdk.jar, etc)
                    are in your application's classpath.
Java 1.3 and 1.4 only: jsecurity.jar, slfj4j-api.jar and one of its bindings, and retroweaver.jar and
                       retroweaver's associated dependendencies


Feature-based dependencies
--------------------------
- If you want to use JSecurity's enterprise session management (heterogeneous clients, SSO support, etc):
  . include ehcache.jar and backport-util-concurrent.jar

- JSecurity Web Filter text-based config ('config' init param) in web.xml or JSecurity code Annotations:
  . include Jakarta commons-beanutils-core.jar
