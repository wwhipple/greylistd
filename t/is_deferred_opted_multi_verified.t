#!/usr/bin/perl -w
#
# User has opted in and isn't whitelisted. 
# Knock once (deferred)
# Knock again (verified)
# Knock again (still verified)
# Knock again (still verified)
# Knock again (still verified)
# Wait past verifification period (deferred)
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
my $second_try_min = '1s';      # Wait 1 seconds to try again
my $second_try_max = '5s';      # Second try within 5 seconds
my $vfy_duration = '10s';       # Verified for 10 seconds
my $log_name  = "$dir/${fname}.log";  # Log file name
my $sock_name = "$dir/${fname}.sock"; # Unix socket file
my $pidf_name = "$dir/${fname}.pid";  # 
my $optin_dir = "$dir/${fname}.optins"; # Opt in domains/addresses
my $ip_whitelistf_name = "$dir/${fname}.ipwhitelist";   # Whitelisted CIDR networks
my $data_name = "$dir/${fname}.data"; # greylistd.data
my $daemon_path = "$parentdir/$daemon_name";

my $relay_ip = '10.10.20.30';
my $relay_net = '10.10.20.0/24';

ok(-x $daemon_path, "$daemon_path exists, is executable");

# Write a config file
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

# Write some opt-in domains/addresses
ok(mkdir($optin_dir), "Created directory $optin_dir");
ok(open(OPTINS, '>', "$optin_dir/moe") != 0, "Opened $optin_dir/moe for writing");
ok(print OPTINS <<"__OPTINS__");
weldon\@whipple.org
micky\@allearsstudios.com
admin\@technoids.org
mabel\@mabellawatkinson.com
zzyzx\@zzyzx.com
whipple.org
allearsstudios.com
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

my $curline = "IS_DEFERRED $relay_ip zzyzx\@zzyzx.com micky\@allearsstudios.com";
my $showgl  = "SHOW_GREYLISTED NOH TOSOCK BATCH";
my $showvfied = "SHOW_VERIFIED NOH TOSOCK BATCH";

##################################
# F I R S T   K N O C K : DEFER
# 

my $host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

my $line = $host->getline();    # Read response
chomp $line;

ok($line eq 'yes', "I've opted in, this is my first knock (I'm deferred)");
$host->close();

#####################################
# S H O W   G R E Y L I S T
#
$host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$showgl\n"), "Sent $showgl to greylistd");

while (my $line = $host->getline()) { # Read what it sends back
    chomp $line;
    if ($line !~ m/^\s*$/) {
        like($line, qr/$relay_net\tzzyzx\@zzyzx.com\tmicky\@allearsstudios.com\t\d{4}\-\d\d\-\d\d\s+\d{1,2}:\d\d:\d\d\t\d{4}\-\d\d\-\d\d\s+\d{1,2}:\d\d:\d\d/, "Matching greylist $line");
    }
}

$host->close();

ok(sleep 3, "Sleeping 3");

##################################
# 2 N D   K N O C K : V E R I F I E D - NOT DEFERRED
# 

$host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

$line = $host->getline();    # Read response
chomp $line;

ok($line eq 'no', "I've opted in, this is my second knock (I waited long enough--I'm verified)");
$host->close();

#####################################
# S H O W   G R E Y L I S T
#
$host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$showvfied\n"), "Sent $showvfied to greylistd");

while (my $line = $host->getline()) { # Read what it sends back
    chomp $line;
    if ($line !~ m/^\s*$/) {
        like($line, qr/$relay_net\tzzyzx\@zzyzx.com\tmicky\@allearsstudios.com\t\d{4}\-\d\d\-\d\d\s+\d{1,2}:\d\d:\d\d/, "Matching verified $line");
    }
}

$host->close();

ok(sleep 3, "Sleeping 3");

##################################
# 3 R D   K N O C K : V E R I F I E D - NOT DEFERRED
# 

$host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

$line = $host->getline();    # Read response
chomp $line;

ok($line eq 'no', "I've opted in, this is my third knock (I didn't wait too long--I'm still verified)");
$host->close();

#####################################
# S H O W   G R E Y L I S T
#
$host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$showvfied\n"), "Sent $showvfied to greylistd");

while (my $line = $host->getline()) { # Read what it sends back
    chomp $line;
    if ($line !~ m/^\s*$/) {
        like($line, qr/$relay_net\tzzyzx\@zzyzx.com\tmicky\@allearsstudios.com\t\d{4}\-\d\d\-\d\d\s+\d{1,2}:\d\d:\d\d/, "Matching verified $line");
    }
}

$host->close();

ok(sleep 3, "Sleeping 3");

##################################
# 4 T H   K N O C K : V E R I F I E D - NOT DEFERRED
# 

$host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

$line = $host->getline();    # Read response
chomp $line;

ok($line eq 'no', "I've opted in, this is my fourth knock (I didn't wait too long--I'm still verified)");
$host->close();

#####################################
# S H O W   G R E Y L I S T
#
$host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$showvfied\n"), "Sent $showvfied to greylistd");

while (my $line = $host->getline()) { # Read what it sends back
    chomp $line;
    if ($line !~ m/^\s*$/) {
        like($line, qr/$relay_net\tzzyzx\@zzyzx.com\tmicky\@allearsstudios.com\t\d{4}\-\d\d\-\d\d\s+\d{1,2}:\d\d:\d\d/, "Matching verified $line");
    }
}

$host->close();

ok(sleep 4, "Sleeping 4");

##################################
# 5 T H   K N O C K : V E R I F I E D - NOT DEFERRED
# 

$host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

$line = $host->getline();    # Read response
chomp $line;

ok($line eq 'no', "Fifth knock. (I didn't wait too long--I'm still verified)");
$host->close();

#####################################
# S H O W   V E R I F I E D
#
$host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$showvfied\n"), "Sent $showvfied to greylistd");

while (my $line = $host->getline()) { # Read what it sends back
    chomp $line;
    if ($line !~ m/^\s*$/) {
        like($line, qr/$relay_net\tzzyzx\@zzyzx.com\tmicky\@allearsstudios.com\t\d{4}\-\d\d\-\d\d\s+\d{1,2}:\d\d:\d\d/, "Matching verified $line");
    }
}

$host->close();

ok(sleep 15, "Sleeping 15 seconds, then I'll try a third time.");

######################################################
# 6 T H   K N O C K : DEFER (Verification expired)
# 
$host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

$line = $host->getline();    # Read response
chomp $line;

ok($line eq 'yes', "Sixth knock after verification period ended. No longer verified");
$host->close();

#####################################
# S H O W   G R E Y L I S T
#
$host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$showgl\n"), "Sent $showgl to greylistd");

while (my $line = $host->getline()) { # Read what it sends back
    chomp $line;
    if ($line !~ m/^\s*$/) {
        like($line, qr/$relay_net\tzzyzx\@zzyzx.com\tmicky\@allearsstudios.com\t\d{4}\-\d\d\-\d\d\s+\d{1,2}:\d\d:\d\d\t\d{4}\-\d\d\-\d\d\s+\d{1,2}:\d\d:\d\d/, "Matching greylist $line");
    }
}

$host->close();

#####################################
# C L E A N   U P
#

ok(system("killall -w $daemon_name") == 0, "Killed the test daemon");
ok(unlink($conf_name, $log_name, $sock_name, $pidf_name, 
          "$optin_dir/moe",
          $ip_whitelistf_name, $data_name), "Cleaned up");
ok(rmdir($optin_dir), "Removed $optin_dir");

exit;


