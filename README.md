Apache Nonce Module
======

A module for Apache designed to implement the script-nonce functionality server-side.

- hello.c
-- This is the first module that we implemented and hooked into Apache httpd.  It successfully returns "hello world" to 
-- the browser when (aws public dns address)/helloworld is the location in the GET

- mod_hello_filter
-- Hello world filter that will eventually become mod_scriptnonce_filter.c

Requirements
======

- GNU GMP Library
- `apt-get install libgcrypt11-dev`
- LIBGCRYPT Library
- `apt-get install zlib1g-dev`

Compilation
======

- apxs2 -cia -lgmp \`libgcrypt-config --cflags --libs\` mod_nonce_filter.c nonce_gen/nonce_rand.c
- (Note for this to work you need to have GMP and LibGCrypt installed)

