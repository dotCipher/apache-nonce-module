cse508
======

A module for Apache designed to implement the script-nonce functionality server-side.

- hello.c
-- This is the first module that we implemented and hooked into Apache httpd.  It successfully returns "hello world" to 
-- the browser when (aws public dns address)/helloworld is the location in the GET

- mod_hello_filter
-- Hello world filter that will eventually become mod_scriptnonce_filter.c

