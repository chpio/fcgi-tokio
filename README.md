# fcgi-rust

**This repo is an archive**

I've stopped working on it after i discovered, that there is no support for fcgi multiplexing in the
Nginx and Apache webservers. That makes fcgi in no way a better fit for backend connections then
HTTP/1.1 already is (HTTP2 is slower due to compression, and encryption). (Besides maybe using it
for the
[*authorizer*](http://www.mit.edu/~yandros/doc/specs/fcgi-spec.html#S6.3) and
[*filter*](http://www.mit.edu/~yandros/doc/specs/fcgi-spec.html#S6.4) roles.)
