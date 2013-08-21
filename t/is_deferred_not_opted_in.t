#!/usr/bin/perl -w
#
# Is email deferred if user/domain hasn't opted in? ('no'!)
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

my @ifaces = `/sbin/ifconfig -a | grep 'inet addr' | grep -v '127\.0\.0\.1'`;
my ($ifaddr) = $ifaces[0] =~ m/inet addr:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;

my $conf_name = "$dir/${fname}.conf"; # Config file name
my $second_try_min = '1s';      # Wait 1 second to try again
my $second_try_max = '5s';      # Second try within 5 seconds
my $vfy_duration = '20s';       # Verified for 20 seconds
my $log_name  = "$dir/${fname}.log";  # Log file name
my $sock_name = "$dir/${fname}.sock"; # Unix socket file
my $pidf_name = "$dir/${fname}.pid";  # 
my $optin_dir = "$dir/${fname}.optins"; # Opt in domain/addresses
my $optin_notify_dir = "$dir/${fname}.tmpoptins";
my $ip_whitelistf_name = "$dir/${fname}.ipwhitelist";   # Whitelisted CIDR networks
my $daemon_path = "$parentdir/$daemon_name";
my $data_name = "$dir/${fname}.data"; # greylistd.data

ok(-x $daemon_path, "$daemon_path exists, is executable");

# Write a config file
ok(mkdir($optin_dir), "Created directory $optin_dir");
ok(mkdir($optin_notify_dir), "Created directory $optin_notify_dir");
ok(open(CONF, '>', "$conf_name") != 0, "Opened $conf_name for writing");
ok(print CONF <<"__CONF__");
dumpfile           = $data_name
log_file           = $log_name
socket             = $sock_name
pidfile            = $pidf_name
optin_dir          = $optin_dir
optin_notify_dir   = $optin_notify_dir
ip_whitelist_file  = $ip_whitelistf_name
second_try_max     = $second_try_max
second_try_min     = $second_try_min
vfy_duration       = $vfy_duration
__CONF__

close(CONF);

# Write some optins
ok(open(OPTINS, '>', "$optin_dir/wwhipple") != 0, "Opened $optin_dir/wwhipple for writing");
ok(print OPTINS <<"__OPTINS__");
whipple.org
allearsstudios.com
technoids.org
weldon\@whipple.org
micky\@allearsstudios.com
admin\@technoids.org
mabel\@mabellawatkinson.com
__OPTINS__

close(OPTINS);

# Write my own interface address (first one returned) in whitelist
ok(open(IPW, '>', "$ip_whitelistf_name") != 0, "Opened $ip_whitelistf_name for writing");
ok(print IPW <<"__IPW__");
${ifaddr}/32
__IPW__

close(IPW);

# Start greylistd
ok(system("$daemon_path", "-d", "--cfg=$conf_name") == 0, "Started $daemon_path");
ok(sleep 5, "Sleep 5 seconds for daemon startup");

##################################
# See if email from/to obfuscated user, connecting from my address is deferred
# (Shouldn't be)

my $curline = "IS_DEFERRED $ifaddr zzyzx\@zzyzx.com zxyzz\@zxyzz.com";
my $host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

my $line = $host->getline();    # Read response
chomp $line;

ok($line eq 'no', "I've not opted in, so email from my own domain (IP_WHITELISTED) is not deferred");

$host->close();

ok(system("killall -w $daemon_name") == 0, "Killed the test daemon");
ok(unlink($conf_name, $log_name, $sock_name, $pidf_name, 
          "$optin_dir/wwhipple",
          $ip_whitelistf_name, $data_name), "Cleaned up");
ok(rmdir($optin_dir), "Removed $optin_dir");
ok(rmdir($optin_notify_dir), "Removed $optin_notify_dir");

exit;


