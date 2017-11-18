# mediadepot
Media download server

A hyper based server with CAS authentication that allows the user to download the media content they created from the You Star project.

## Non-Authenticated API points:
* `/health - GET/HEAD` This path lets us know that the server is running.
* `/resources - GET/HEAD` This path is where css and images are stored and served up.
* `/logout - GET` This path is always available since user may be authenticated but not have authorization as not all users have an entry in the vcms directory. When the user gets directed here their session cookie will be removed and they will get redirected to the CAS logout application.

## Authenticated API points:
* `/ - GET` This path is where the use will go to get their application and see what media files they created via the YouStar program.
* `/library - GET/HEAD/DELETE` This path is used to manage the users files. They may check size (HEAD), download (GET), or remove (DELETE) them. Their id they used to authenticate and the path to the library directory will get prepended to this path to find the file requested.
