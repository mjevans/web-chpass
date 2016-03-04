#!/usr/bin/perl
#
# NiPasswd.pm - perl interface to the "nipasswd" program.
#
# See perl POD documentation at end.
# To view, run:  perldoc NiPasswd.pm
#
# Part of the "web-chpass" package.
# https://github.com/chip-rosenthal/web-chpass
#
# Chip Rosenthal
# <chip@unicom.com>
#

use strict;
use warnings;
use File::Temp qw(tempfile);
use IO::File;
package NiPasswd;

our $PATH_NIPASSWD = "/usr/local/lib/web-chpass/nipasswd";
our $DEBUG = 0;

require Exporter;
use vars qw(@ISA @EXPORT);
@ISA = qw(Exporter);
@EXPORT = qw($PATH_NIPASSWD $DEBUG);


sub _run_nipasswd
{
	die 'usage: _run_nipasswd($input_file, [$options, ...])'
		unless(@_ > 0);
	my $input_file = shift;
        if ($DEBUG) {
                unshift(@_, "-D");
        }
	my $options = join(' ', @_);

	#
	# Startup "nipasswd".
	#
	open(FP, "-|", "$PATH_NIPASSWD $options <$input_file 2>&1")
		or die("SYSTEM ERROR: pipe($PATH_NIPASSWD) failed: $!");

	#
	# Retrieve the results from "nipasswd."
	#
	my $resp = join("", <FP>);
	close(FP);
	my $rc = $?;

	if (($rc & 0xFF) != 0) {
		# Process did not exit normally.
		$rc = -1;
		$resp = sprintf("exit status 0x%04x", $rc);
	} else {
		$rc = ($rc & 0xFF00) >> 8;
	}
	return ($rc, $resp);
}


sub change_passwd
{
	die 'usage: NiPasswd::change_passwd($username, $old_password, $new_password)'
		unless(@_ == 3);
	my($username, $old_password, $new_password) = @_;

	my($fh, $fname) = main::tempfile(UNLINK => 1)
		or die("SYSTEM ERROR: tempfile failed: $!");
	$fh->print($username, "\n");
	$fh->print($old_password, "\n");
	$fh->print($new_password, "\n");
	$fh->close();

	my @ret = _run_nipasswd($fname);
	unlink($fname);
	return @ret;
}


sub auth_user
{
	die 'usage: NiPasswd::auth_user($username, $password)'
		unless(@_ == 2);
	my($username, $password) = @_;

	my($fh, $fname) = main::tempfile(UNLINK => 1)
		or die("SYSTEM ERROR: tempfile failed: $!");
	$fh->print($username, "\n");
	$fh->print($password, "\n");
	$fh->close();

	my @ret = _run_nipasswd($fname, '-a');
	unlink($fname);
	return @ret;
}


1;

__END__

=head1 NAME

NiPasswd - non-interactive password change or verify

=head1 SYNOPSIS

 use lib "/usr/local/lib/web-chpass";
 use NiPasswd;

 $NiPasswd::PATH_NIPASSWD = "/usr/local/lib/web-chpass/nipasswd";

 ($rc, $resp) = NiPasswd::auth_user($username, $password);
 ($rc, $resp) = NiPasswd::change_passwd($username, $old_password, $new_password);

=head1 DESCRIPTION

The "NiPasswd" module is a perl interface to the I<nipass(8)> utility.
It allows scripts to authenticate users and change passwords through
the I<pam(8)> subsystem.  It provides these functions to non-privileged
programs in a fairly secure and trustworthy fashion.

The following functions are provided:

=over 4

=item B<NiPasswd::auth_user()>

Authenticate a user through the PAM subsystem, given the specified
I<username> and I<password>.

=item B<NiPasswd::change_password()>

First, authenticate a user through the PAM subsystem, given the specified
I<username> and I<old_password>.  If authentication passes, then change
the account password to I<new_password>.

=back

Both of these routines return an list of two values.  The first value
is one of the following numeric status codes:

    -1    process did not exit normally
    0     password successfully changed (EX_SUCCESS)
    1     failed due to an error (EX_ERROR)
    2     failed due to username/password auth (EX_DENIED)
    3     failed due to bad password checks (EX_BADPW)

The second value will be a diagnostic message that may be displayed to
the user on a non-zero status.  It contains the output produced by
I<nipasswd(8)>, and usually represents some diagnostic from the PAM
system.

The following global parameters are provided to configure the "NiPasswd"
system:

=over 4

=item B<$NiPasswd::PATH_NIPASSWD>

Pathname to the I<nipasswd(8)> command.  This may be used if the
default value I</usr/local/lib/web-chpass/nipasswd> is not correct.

=item B<$NiPasswd::DEBUG>

If set non-zero, enables debugging output from I<nipasswd>.

=back

=head1 NOTES

This module is just a wrapper around I<nipasswd(8)>.  See the manpage
for that utility.  The limits and caveats apply here too.

=head1 AUTHOR

 Chip Rosenthal
 Unicom Systems Development
 <chip@unicom.com>

 This module is part of the "web-chpass" package.
 Visit http://www.unicom.com/sw/web-chpass/ for more info.

 $Id: NiPasswd.pm,v 1.2 2002/07/21 21:29:23 chip Exp $

