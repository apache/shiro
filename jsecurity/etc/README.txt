Don't get confused by the files!!!  A little explanation will help you choose the jars
right for your application.

Here's what they mean:

Really Fast Fast-Start
----------------------
Just use jsecurity.jar.  It includes everything you need.  If you want to make your deployment
process and dependency management as efficient as possible, keep reading.


Convenience Jars
-----------------

* jsecurity.jar
- Convenience jar that includes everything - i.e. everything inside the jsecurity-api.jar,
  jsecurity-ri-common.jar, jsecurity-ri-business.jar, and jsecurity-ri-client.jar.

  You can use only this jar and ignore all others for the quickest and fastest way to
  use JSecurity.  Just realize you may not be deploying things in the most efficient manner
  (explained below).

* jsecurity-business.jar
- Convenience jar that includes everything inside the jsecurity-api.jar, jsecurity-ri-common.jar
  and jsecurity-ri-business.jar.  For efficient use on the business-tier only (explained below).

* jsecurity-client.jar
- Convenience jar that includes everything inside the jsecurity-api.jar, jsecurity-ri-common.jar
  and jsecurity-ri-client.jar files.  For efficient use on the client-tier only (explained below).


Build Jars
----------

* jsecurity-api.jar
- Just the JSecurity API "specification" without the reference implementation.
- You need this jar if you wish to compile against JSecurity "specification" interfaces and
  classes (but not the reference implementation).  For example, you can specify this jar in your
  IDE or Ant classpath settings and you'll be able to compile.

* jsecurity-ri-common.jar
- JSecurity reference implementation's common classes and files.
- If you're using the JSecurity reference implementation during runtime, and you're writing a
  client/server architecture, this common jar needs to be in both the client _and_
  business (a.k.a. server) classpaths during runtime.

* jsecurity-ri-business.jar
- JSecurity reference implementation's business-tier classes and files.
- If you're using the JSecurity reference implementation during runtime, and you're writing a
  client/server architecture, this "business" jar needs to be in the business-tier
  (a.k.a. server-tier) classpath during runtime.

* jsecurity-ri-client.jar
- JSecurity reference implementation's client-tier classes and files.
- If you're using the JSecurity reference implementation during runtime, and you're writing a
  client/server architecture, this client jar needs to be in the client classpath during
  runtime.


Packaging Explanation
----------------------
Depending on your architecture, you may wish to include certain jars inside certain classpaths
to have fine grained control over dependencies and deployment file size.

If writing a client/server application, you should deploy only the api, common, and client jars
to the client application (e.g. a Swing application or Applet).  This guarantees the
smallest possible subset of jars required to run the client app (thereby ensuring faster
download times when starting up).  Those 3 jars have been consolidated for your convenience
in the jsecurity-client.jar file.  Only that file needs to be downloaded by a Java Web Start or
Applet application that interacts with a remote business server.

Only the api, common and business jars need to be deployed on the business tier (a.k.a. the
server tier).  Those 3 jars have been consolidated for your convenience in the
jsecurity-business.jar file.

If your application performs both "client" and "business" operations, such as in the case
of a standalone Swing application or a pure web application (no remoting), or a server that acts
as a client to another server, then you'll need all four build jars.  All of these jars have been
consolidated for your convenience in the jsecurity.jar file.

Use the file(s) that makes sense for your application.  If you want the fastest download for
a remote client, have that client download the jsecurity-client.jar file only.  If you don't
care about dowload size, or the file will reside on a server, just use the jsecurity.jar file
for simplicity's sake.  The choice is yours.

For more in-depth reasoning on why these smaller jars may be beneficial to you, read the
OnJava.com article: http://www.onjava.com/pub/a/onjava/2005/06/22/modularant.html

Cheers,

The JSecurity Team