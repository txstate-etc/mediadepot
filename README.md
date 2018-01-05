# mediadepot
Media download server

A hyper based server with CAS authentication that allows the user to download the media content they created from the You Star project.

## Non-Authenticated API points:
* `/health - [GET|HEAD]` This path lets us know that the server is running.
* `/resources/<rest_of_file_path> - [GET|HEAD]` This path is where css and images are stored and served up.
* `/logout - [GET]` This path is always available since user may be authenticated but not have authorization as not all users have an entry in the vcms directory. When the user gets directed here their session cookie will be removed and they will get redirected to the CAS logout application.

## Authenticated API points:
* `/ - [GET]` This path is where the user will go to get their application and see what media files they created via the YouStar program.
* `/library/<rest_of_file_path> - [GET|HEAD|DELETE]` This path is used bay a CAS authenticated user to manage the their files. They may check size (HEAD), download (GET), or remove (DELETE) them. Their id they used to authenticate and the path to the library directory will get prepended to this path to find the file requested. NOTE: DELETE may never be implemented depending on required features.
* `/admin/<rest_of_file_path> - [GET|<HEAD>|DELETE]` This  path is used by an admin to view and access user files. The request is authorized with a Json Web Token relayed via Authorization Bearer http header. The rest of the path simulates the previous two "/" and "/library" API points. Generally a "/" request will be accompanied with a "application/json" Content Type.

## Environment variables:
* `ADDRESS` This is the address and port that the server will bind. The default is `127.0.0.1:8443`
* `MASTERKEY` This is a base64 encoded 32 byte key used to sign the session cookies after CAS authentication. If one is not provided then it will randomly be generated by the application. This should be set to maintain sessions between restarts of the application. Example of generating master key: `openssl rand -base64 32`
* `JWTKEY` This is a base64 encoded 64 byte key used to sign JSON Web Tokens (JWT) for adminstrative requests via the `/admin` API. There is no default set for this and the service will terminate if one is not assigned. Example of generating JWT key: `openssl rand -base64 64`
* `ROOTDIR` This is the directory where the `/resources` and `/vcms/<id>/library` directories are stored.  The default is `/var/lib/www`
* `DOMAIN` This is the protocol, name of the server, and port that the user sees. An example would be `https://mediadepot.its.txstate.edu:8443` domain. The application will not start without this field being defined.
* `CASURL` This is the address of the CAS server. An example would be `https://login.its.txstate.edu`, however, note that some universities require the cas path added to the end like `https://login.its.txstate.edu/cas` as their tomcat application is not running under the ROOT path but under rather the cas directory.
* `SSL_CERT_FILE` /etc/ssl/certs/ca-certificates.crt
* `SSL_CERT_DIR` /etc/ssl/certs

## ROOTDIR subdirectories:
* `/resources` This is where the images, css, and other files that support the user interface reside.
* `/private` This is where the SSL certificates are stored. Note that the application expects to use SSL and will not start without them.
* `/vcms` This is where all the created video content will be placed. The filesystem is broken up into user id's. All user video content will be placed within a library directory under the associated user directory.

## docker examples:
```
docker build --target deploy -t ${TXSTATE_REGISTRY}/mediadepot:0.1.1 .
docker run --rm --env-file ~+/www/env.txt --read-only -v ~+/www:/var/lib/www:ro -p 127.0.0.1:8443:8443 --name mediadepot ${TXSTATE_REGISTRY}/mediadepot:0.1.1
```

## TODOs:
* Design templates to fill in with user content.
