Apache Shiro Runtime Requirements
------------------------------

All 3rd party dependencies mentioned below are accessible in two ways:
1) In the shiro-<version>-with-dependencies.zip distribution's lib directory
2) After downloading shiro-<version>.zip (no dependencies), run 'ant retrieve-dependencies'.  This will download
the dependencies to a lib directory (peer to the build.xml).


Minimal required dependencies
-------------
Ensure shiro-all.jar, slf4j-api.jar and one of slf4j's bindings (slf4j-simple.jar, slf4j-log4j12, etc) are in
your application's classpath.


Feature-based dependencies
--------------------------
- .ini based configuration, either for a shiro.ini file in the classpath or embedded .ini in the ShiroFilter
  in web.xml:
  . include Jakarta commons-beanutils-core.jar
