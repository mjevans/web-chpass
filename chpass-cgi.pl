#!/usr/bin/perl
#
# chpass-cgi.pl - The "Change My Password by Web" program.
#
# This script can be installed as a CGI, but normally isn't.  Instead, it
# usually lives in the "web-chpass" library dir, and a small "chpass.cgi"
# script is used to initialize the environment and then start this up.
# That way we shouldn't have to modify this script with site-specific
# information.
#
# The environment parameters we use are:
#
#	CHPASS_LIBDIR - Pathname to the "web-chpass" library.
#
#	CHPASS_TEMPLATE - Name of the HTML template to use.  Either a full
#	pathname or name of a file in $CHPASS_LIBDIR.
#
#	CHPASS_BADPW_CHECKS - Bad password check mode.	Possible values
#	are: "enabled", "disabled", or "optional".
#
#	FORCE_HTTPS - Force insecure connections (http) to secure
#	connections (https).  Possible values are: enabled, disabled.
#

BEGIN {
	use vars qw(%ENV $LIBDIR);
	$LIBDIR = $ENV{'CHPASS_LIBDIR'} || "/usr/local/lib/web-chpass";
}

use strict;
use warnings;
use lib $LIBDIR;
use NiPasswd;
use CGI;
use CGI::Carp qw(fatalsToBrowser);
use Template;

$NiPasswd::PATH_NIPASSWD = "$LIBDIR/nipasswd";
my $Template = $ENV{'CHPASS_TEMPLATE'} || "chpass.tmpl";
my $Badpw_checks = $ENV{'CHPASS_BADPW_CHECKS'} || "optional";
my $Force_https = $ENV{'FORCE_HTTPS'} || "enabled";


sub send_doc
{
	my ($vars) = @_;

	my $tt = Template->new({
		INCLUDE_PATH => $LIBDIR,
		INTERPOLATE => 1,
	}) || die "$Template::ERROR\n";

	my $output = "";
	$tt->process($Template, $vars, \$output)
		|| die $tt->error(), "\n";

	print
		"Content-Type: text/html\r\n",
		"Content-Length: ", length($output), "\r\n",
		"\r\n",
		$output;
	exit(0);
}


sub send_redirect
{
	my($location) = @_;
	print("Location: " . $location . "\r\n\r\n");
	exit(0);
}


##############################################################################
#
# start of execution
#


if ($Force_https ne "disabled" && $ENV{'HTTPS'} ne "on") {
	send_redirect("https://" . $ENV{'SERVER_NAME'} . $ENV{'REQUEST_URI'});
}

my $q = new CGI;

my $vars = {
	message => {
		content => "",
		class => "alert",
	},
	form => {
		enable => 1,
		enable_badpw_check => ($Badpw_checks eq "optional"),
		username => "",
		badpw_check => 1,
	},
};

#
# If the action field isn't set, assume the CGI is just starting up
# and display the "change password" form.
#
if (!$q->param('action') || $q->param('action') ne "chpass") {
	send_doc($vars);
}

#
# Retrieve and verify the form parameters.
#

my $username = $q->param('username');
if (! $username) {
	$vars->{'message'}->{'content'} = "You need to enter your username.  Please try again.";
	send_doc($vars);
}
$username =~ s/@.*//;
$vars->{'form'}->{'username'} = $username;

my $old_passwd = $q->param('old_passwd');
if (! $old_passwd) {
	$vars->{'message'}->{'content'} = "You need to enter your old password.  Please try again.";
	send_doc($vars);
}

my $new_passwd = $q->param('new_passwd');
if (! $new_passwd) {
	$vars->{'message'}->{'content'} = "You need to enter the new password you want.  Please try again.";
	send_doc($vars);
}

my $new_passwd2 = $q->param('new_passwd2');
if (! $new_passwd2) {
	$vars->{'message'}->{'content'} = "You need to enter the new password a second time to confirm.  Please try again.";
	send_doc($vars);
}
if ($new_passwd ne $new_passwd2) {
	$vars->{'message'}->{'content'} = "The new passwords you entered don't match.  Please try again.";
	send_doc($vars);
}

#
# Determine whether to do bad password checking.
#
if ($Badpw_checks eq "enabled") {
	$NiPasswd::STRICT_CHECKS = 1;
} elsif ($Badpw_checks eq "disabled") {
	$NiPasswd::STRICT_CHECKS = 0;
} elsif ($Badpw_checks eq "optional") {
	$NiPasswd::STRICT_CHECKS = !!$q->param('strict_checks');
} else {
	die("CONFIGURATION ERROR: bad CHPASS_BADPW_CHECKS setting");
}

#
# Run the password changer.
#
my ($rc, $resp) = NiPasswd::change_passwd($username, $old_passwd, $new_passwd);

#
# The "nipasswd" exit codes are:
#
#	-1		process did not exit normally
#	0 - EX_SUCCESS	password successfully changed
#	1 - EX_ERROR	failed due to an error
#	2 - EX_DENIED	failed due to username/password auth
#	3 - EX_BADPW	failed due to bad password checks
#

if ($rc < 0) {
	# Process did not exit normally.
	die($resp);
}

if ($rc == 0) {
	$vars->{'message'}->{'content'} = "Done!  Your password has been changed.";
	$vars->{'message'}->{'class'} = "success";
	$vars->{'form'}->{'enable'} = 0;
	send_doc($vars);
}

if ($rc == 2) {
	$resp =~ s/^/Password not changed. /;
	$vars->{'message'}->{'content'} = $resp . "<br />Check that you entered your username and current password correctly.";
	send_doc($vars);
}

if ($rc == 3) {
	$resp =~ s/^BAD PASSWORD:\s+/The password you selected is bad, because /;
	$resp =~ s/^/Password not changed. /;
	$resp .= "<br />Please pick a better password and try again.";
	$vars->{'message'}->{'content'} = $resp;
	send_doc($vars);
}

$vars->{'message'}->{'content'} = "Password not changed. " . $resp;
send_doc($vars);
#NOTREACHED
