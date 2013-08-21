#!/usr/bin/perl -w
#
# Is the specified IP address whitelisted?
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
my $second_try_min = '1s';      # Wait 1 second to try again
my $second_try_max = '5s';      # Second try within 5 seconds
my $vfy_duration = '10s';       # Verified for 20 seconds
my $log_name  = "$dir/${fname}.log";  # Log file name
my $sock_name = "$dir/${fname}.sock"; # Unix socket file
my $pidf_name = "$dir/${fname}.pid";  # 
my $optin_dir = "$dir/${fname}.optins"; # Opt in domains/addresses
my $ip_whitelistf_name = "$dir/${fname}.ipwhitelist";   # Whitelisted CIDR networks
my $data_name = "$dir/${fname}.data"; # greylistd.data
my $daemon_path = "$parentdir/$daemon_name";

ok(-x $daemon_path, "$daemon_path exists, is executable");

# Write a config file
ok(mkdir($optin_dir), "Created directory $optin_dir");
ok(open(CONF, '>', "$conf_name") != 0, "Opened $conf_name for writing");
ok(print CONF <<"__CONF__");
dumpfile           = $data_name
log_file           = $log_name
socket             = $sock_name
pidfile            = $pidf_name
optin_dir          = $optin_dir
ip_whitelist_file  = $ip_whitelistf_name
second_try_max     = $second_try_max
second_try_min     = $second_try_min
vfy_duration       = $vfy_duration
__CONF__

close(CONF);

# Write some opt-in domains
ok(open(OPTINS, '>', "$optin_dir/harry") != 0, "Opened $optin_dir/harry for writing");
ok(print OPTINS <<"__OPTINS__");
whipple.org
allearsstudios.com
weldon\@whipple.org
micky\@allearsstudios.com
admin\@technoids.org
mabel\@mabellawatkinson.com
zzyzx\@zzyzx.com
technoids.org
__OPTINS__

close(OPTINS);

# Write my own interface address (first one returned) in whitelist
ok(open(IPW, '>', "$ip_whitelistf_name") != 0, "Opened $ip_whitelistf_name for writing");
ok(print IPW <<"__IPW__");
64.233.160.0/19   \# Google
66.102.0.0/20 66.249.80.0/20 72.14.192.0/18 74.125.0.0/16 \# Google
209.85.128.0/17   \# Google
216.239.32.0/19   \# Google
__IPW__

close(IPW);

# Start greylistd
ok(system("$daemon_path", "-d", "--cfg=$conf_name") == 0, "Started $daemon_path");
ok(sleep 5, "Sleep 5 seconds for daemon startup");

##################################
# I S   W H I T E L I S T E D   I P? YES
# 

my $host = '';
my $curline = "IS_WHITELISTED_IP 74.125.123.124";

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

my $line = $host->getline();    # Read response
chomp $line;

ok($line eq 'yes', "IP 74.125.123.124 is whitelisted");
$host->close();

#####################################
# I S   W H I T E L I S T E D   I P? NO
#
$host = '';
$curline = "IS_WHITELISTED_IP 10.10.20.5";

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

my $line = $host->getline();    # Read response
chomp $line;

ok($line eq 'no', "IP 10.10.20.5 is NOT whitelisted");
$host->close();

#####################################
# C L E A N   U P
#

ok(system("killall -w $daemon_name") == 0, "Killed the test daemon");
ok(unlink($conf_name, $log_name, $sock_name, $pidf_name, 
          "$optin_dir/harry",
          $ip_whitelistf_name, $data_name), "Cleaned up");
ok(rmdir($optin_dir), "Removed $optin_dir");
exit;


