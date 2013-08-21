#!/usr/bin/perl -w
#
# Test case to test optin domains 
#
use strict;
use IO::Socket;
use IO::File;
use Cwd qw(abs_path);
use Test::More qw( no_plan );

BEGIN { use_ok( 'Linux::Inotify2' ); }
require_ok( 'Linux::Inotify2' );

die "Must be root to run this test." if $<;

ok($< == 0, "Running as root");
my $path = abs_path($0);
my ($dir, $parentdir, $fname) = $path =~ m/^((.*)\/[^\/]+)\/([^\/]+)$/;
my $daemon_name = 'greylistd';
system("killall -w -q $daemon_name");
my $conf_name = "$dir/${fname}.conf"; # Config file name
my $log_name  = "$dir/${fname}.log";  # Log file name
my $sock_name = "$dir/${fname}.sock"; # Unix socket file
my $pidf_name = "$dir/${fname}.pid";  # 
my $optin_dir = "$dir/${fname}.optins"; # Opt in domain names
my $data_name = "$dir/${fname}.data"; # greylistd.data
my $daemon_path = "$parentdir/$daemon_name";

ok(-x $daemon_path, "$daemon_path exists, is executable");

# Write a config file
ok(open(CONF, '>', "$conf_name") != 0, "Opened $conf_name for writing");
ok(print CONF <<"__CONF__");
dumpfile           = $data_name
log_file           = $log_name
socket             = $sock_name
pidfile            = $pidf_name
optin_dir          = $optin_dir
__CONF__

close(CONF);

# Write some opt-in domains
ok(mkdir($optin_dir), "Created directory $optin_dir");
ok(open(OPTIND, '>', "$optin_dir/smiegel") != 0, "Opened $optin_dir/smiegel for writing");
ok(print OPTIND <<"__OPTIND__");
whipple.org
allearsstudios.com
technoids.org
__OPTIND__

close(OPTIND);

# Start greylistd
ok(system("$daemon_path", "-d", "--cfg=$conf_name") == 0, "Started $daemon_path");
ok(sleep 5, "Sleep 5 seconds for daemon startup");

my $curline = 'SHOW_OPTIN TOSOCK DOMAINS NOH';
my $host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

while (my $line = $host->getline()) { # Read what it sends back
    chomp $line;
    if ($line !~ m/^\s*$/) {
        like($line, qr/whipple.org|allearsstudios.com|technoids.org/, "Found domain $line");
    }
}

$host->close();

ok(system("killall -w $daemon_name") == 0, "Killed the test daemon");
ok(unlink($conf_name, $log_name, $sock_name, $pidf_name, "$optin_dir/smiegel", $data_name), "Cleaned up");
ok(rmdir($optin_dir), "Removed $optin_dir");

exit;


