# web-chpass

The "web-chpass" package provides a web application to allow users
to change their password.  This package was written with security and
flexibility as the primary concerns -- and in that order.

This package runs on systems that use PAM to manage user authorizations.
It can be used in LDAP environments.

The package was originally written to run under Red Hat Linux version 7.2.
The current version has been tested with Debian Linux version 8 ("Jessie").
I welcome reports (and patches) for other systems.

There are two parts to the package.

  * nipasswd - allows non-privileged programs to authenticate users
    and change passwords in a fairly secure and reliable fashion.
    The "NiPasswd.pm" perl module is a scripted interface to "nipasswd".

  * chpass - A web application that implements the "Change
    My Password" function. This requires Perl and the (widely available)
    Perl Template Toolkit.


## Rationale

There are numerous "change my password" web applications available.
Unfortunately, most do not follow good security design practices.

The problem is that password authentication and changing is a privileged
function, thus must be done by the superuser.  So, a system designed to
do password changing through the web will have at least one setuid=root
component.

Good security practices dictate this component be small, auditable, and
reliable.  Unfortunately, this often is not the case.  For instance, many
of these applications generate HTML documents and manipulate (tainted)
user input within a privileged context.

The web-chpass system presents three layers, not only to meet the security
requirements, but also to provide install flexibility.

The layers are:

  * The "nipasswd" non-interactive password changing utility.  This is
    a small, compiled program that is installed setuid=root.  It's
    only function is to authenticate users and change their passwords.

  * A "chpass" CGI script to implement a "change my password"
    function.  It retrieves information from a web form, performs
    some first-level data validations, and then invokes "nipasswd".
    This contains no HTML, and so shouldn't require changes.

  * An HTML template that produces the content and is easily
    customized.


## Author

This document is part of the "web-chpass" package.
https://github.com/chip-rosenthal/web-chpass

Chip Rosenthal
<chip@unicom.com>
