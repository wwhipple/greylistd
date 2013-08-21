#!/usr/bin/perl -w
#
# Test case to make sure wildcard optins work (witn inotify, etc).
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
my $ip_whitelistf_name = "$dir/${fname}.ipwhitelist";   # Whitelisted CIDR networks
my $rbl_whitelistf_name = "$dir/${fname}.rblwhitelist"; # Realtime black-hole list
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
optin_dir          = *
ip_whitelist_file  = $ip_whitelistf_name
ip_whitelist_file  = $rbl_whitelistf_name
second_try_max     = $second_try_max
second_try_min     = $second_try_min
vfy_duration       = $vfy_duration
__CONF__

close(CONF);

# Skip writing optins

# Write some whitelisted IP CIDR designations
ok(open(IPW, '>', "$ip_whitelistf_name") != 0, "Opened $ip_whitelistf_name for writing");
ok(print IPW <<"__IPW__");
127.0.0.0/8

17.148.16.100/30 17.148.16.104/32 17.148.16.105/32 \# Apple SMTP pool

12.5.136.141/32 12.5.136.142/32 12.5.136.143/32 12.5.136.144/32 63.169.44.143/32 63.169.44.144/32 \# Southwest Airlines
12.107.209.244/32  \# kernel.org
12.107.209.250/32  \# sourceware.org
209.132.176.174/32 \# sourceware.org mailing lists (unique sender)
64.7.153.18/32     \# sentex.ca
63.82.37.110/32    \# SLmail

64.12.136.0/24 64.12.137.0/24 64.12.138.0/24 \# AOL
152.163.225.0/24  \# AOL
205.188.0.0/16    \# AOL
__IPW__

close(IPW);

# Write some whitelisted IP CIDR designations
ok(open(RBL, '>', "$rbl_whitelistf_name") != 0, "Opened $rbl_whitelistf_name for writing");
ok(print RBL <<"__RBL__");
209.63.57.0/24
69.89.16.0/20
66.147.240.0/20
74.220.192.0/19
67.222.32.0/19
70.40.192.0/19
67.20.64.0/18
__RBL__

close(RBL);


# Start greylistd
ok(system("$daemon_path", "-d", "--cfg=$conf_name") == 0, "Started $daemon_path");
ok(sleep 5, "Sleep 5 seconds for daemon startup");

##################################
# Test opt-in domains first

my $curline = 'SHOW_OPTIN TOSOCK DOMAINS NOH';

my $host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

while (my $line = $host->getline()) { # Read what it sends back
    chomp $line;
    if ($line !~ m/^\s*$/) {
        like($line, qr/All recipient addresses\/domains have opted in \(wildcard \* in the configuration file\)\./, "Optin domains are wildcarded");
    }
}

$host->close();

###################################
# Then opt-in addresses
$curline = 'SHOW_OPTIN TOSOCK ADDRS NOH';

$host="";

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

while (my $line = $host->getline()) { # Read what it sends back
    chomp $line;
    if ($line !~ m/^\s*$/) {
        like($line, qr/All recipient addresses\/domains have opted in \(wildcard \* in the configuration file\)\./, "Optin addresses are wildcarded");
    }
}

$host->close();

###################################
# Now test whitelists
$curline = 'SHOW_WHITELIST TOSOCK NOH';

$host="";

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

while (my $line = $host->getline()) { # Read what it sends back
    chomp $line;
    if ($line !~ m/^\s*$/) {
        like($line, qr{127.0.0.0/8
             |17.148.16.100/30|17.148.16.104/32|17.148.16.105/32  # Apple SMTP pool
             |12.5.136.141/32|12.5.136.142/32|12.5.136.143/32|12.5.136.144/32|63.169.44.143/32|63.169.44.144/32 # Southwest Airlines
             |12.107.209.244/32  # kernel.org
             |12.107.209.250/32  # sourceware.org
             |209.132.176.174/32 # sourceware.org mailing lists (unique sender)
             |64.7.153.18/32     # sentex.ca
             |63.82.37.110/32    # SLmail
             |64.12.136.0/24|64.12.137.0/24|64.12.138.0/24 # AOL
             |152.163.225.0/24   # AOL
             |205.188.0.0/16     # AOL
             |209.63.57.0/24     # rbl_whitelist starts here 
             |69.89.16.0/20
             |66.147.240.0/20
             |74.220.192.0/19
             |67.222.32.0/19
             |70.40.192.0/19
             |67.20.64.0/18
         }x, "Found domain $line");
    }
}

$host->close();

$curline = "IS_DEFERRED $relay_ip zzyzx\@zzyzx.com micky\@allearsstudios.com";
my $showgl  = "SHOW_GREYLISTED NOH TOSOCK BATCH";
my $showvfied = "SHOW_VERIFIED NOH TOSOCK BATCH";

##################################
# F I R S T   K N O C K : DEFER
# 

$host = '';

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

ok(sleep 2, "Sleeping 2");

##################################
# S E C O N D   K N O C K : NOT DEFERRED
# 

$host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

$line = $host->getline();    # Read response
chomp $line;

ok($line eq 'no', "Second knock, now I'm verified");
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
# T H I R D   K N O C K : DEFER (Verification expired)
# 
$host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

$line = $host->getline();    # Read response
chomp $line;

ok($line eq 'yes', "Verification period ended. No longer verified");
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


ok(system("killall -w $daemon_name") == 0, "Killed the test daemon");
ok(unlink($conf_name, $log_name, $sock_name, $pidf_name, 
          $ip_whitelistf_name, $rbl_whitelistf_name, $data_name), "Cleaned up");
exit;


