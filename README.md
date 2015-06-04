Java Sample Code for Moxtra APIs
================================

This repository contains Java code samples to help you get started in integrating Moxtra APIs into your application. 

Please feel free to clone the repository and use the example code.

For the detailed documentation on Moxtra APIs please visit http://developer.moxtra.com

## How to run

This sample is a web application "apiutil.war" that is on /target/apiutil.war, which can be deployed on any 
Java Web Server. For example on Tomcat, you can visit the first page on http://localhost:8080/apiutil/index.html to 
see the samples as follows:

  + Create access_token via unique_id
  + Upload User Picture
  + Create Binder
  + Upload Binder Cover
  + Upload Page into Binder
  + Upload File into Meet
  + Invoke Get API 
  + Invoke Post API
  + Invoke Delete API

## Samples

Using web pages to drive server operations. Each web page performs one function. The upload file operations are to get 
files from server, not client. In other words, server codes are client to Moxtra REST API Service. 

  + The Servlet is handled by /src/main/java/com/moxtra/webapp/api/APIServlet.java
  + The server operations are handled by /src/main/java/com/moxtra/util/MoxtraAPIUtil.java

## Build by Maven

This project can be built by Maven via "mvn clean install".



