#!/usr/bin/perl -w
#
# Test case to see if inotify detects modification of files (during
# runtime) containing optin addresses/domains and whitelisted addresses
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
my $optin_dir = "$dir/${fname}.optins"; # Opt in domain/addresses
my $ip_whitelistf_name = "$dir/${fname}.ipwhitelist";   # Whitelisted CIDR networks
my $rbl_whitelistf_name = "$dir/${fname}.rblwhitelist"; # Realtime black-hole list
my $data_name = "$dir/${fname}.data"; # greylistd.data
my $daemon_path = "$parentdir/$daemon_name";

ok(-x $daemon_path, "$daemon_path exists, is executable");

# Write a config file
ok(mkdir($optin_dir), "Created directory $optin_dir");
ok(open(CONF, '>', "$conf_name") != 0, "Opened $conf_name for writing");
ok(print CONF <<"__CONF__");
log_file           = $log_name
socket             = $sock_name
pidfile            = $pidf_name
optin_dir          = $optin_dir
ip_whitelist_file  = $ip_whitelistf_name
ip_whitelist_file  = $rbl_whitelistf_name
dumpfile           = $data_name
__CONF__

close(CONF);

# Write some opt-in domains
ok(open(OPTINS, '>', "$optin_dir/root") != 0, "Opened $optin_dir/root for writing");
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
        like($line, qr/whipple.org|allearsstudios.com|technoids.org/, "Found domain $line");
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
        like($line, qr/weldon\@whipple.org|micky\@allearsstudios.com|admin\@technoids.org|mabel\@mabellawatkinson.com/, "Found domain $line");
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

############################################################
# Delete lines from root's opt-in; make sure we detect it.
#
ok(open(OPTIN2, '>', "$optin_dir/root") != 0, "Opened $optin_dir/root for writing");
ok(print OPTIN2 <<"__OPTIN2__");
technoids.org
allearsstudios.com
weldon\@whipple.org
micky\@allearsstudios.com
mabel\@mabellawatkinson.com
__OPTIN2__

close(OPTINS);

##################################
# Re-test shortened optins

$curline = 'SHOW_OPTIN TOSOCK DOMAINS NOH';
$host = '';

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

while (my $line = $host->getline()) { # Read what it sends back
    chomp $line;
    if ($line !~ m/^\s*$/) {
        like($line, qr/allearsstudios.com|technoids.org/, "Found domain $line");
    }
}

$host->close();

# Now add a line to rbl_whitelist. Verify that it was detected.
# Write some whitelisted IP CIDR designations
ok(open(RBL2, '>', "$rbl_whitelistf_name") != 0, "Opened $rbl_whitelistf_name for writing");
ok(print RBL2 <<"__RBL2__");
209.63.57.0/24
69.89.16.0/20
66.147.240.0/20
74.220.192.0/19
67.222.32.0/19
70.40.192.0/19
67.20.64.0/18
166.70.98.32/29
__RBL2__

close(RBL2);

###################################
# Re-test augmented whitelist domains (This should reload
# ALL whitelist files
$curline = 'SHOW_WHITELIST TOSOCK NOH';

$host="";

# Open a connection to the Unix domain socket:
ok(($host = IO::Socket::UNIX->new(Peer  => $sock_name, Type  => SOCK_STREAM )) != 0, "Created Socket");
ok($host->autoflush(1), "Turned on autoflush");

ok($host->print("$curline\n"), "Sent $curline to greylistd");

my $found_new = 0;
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
             |166.70.98.32/29
         }x, "Found domain $line");
        if ($line eq '166.70.98.32/29') {
            $found_new = 1;
        }
    }
}

$host->close();
ok($found_new, "Found the newly added IP address 166.70.98.32/29");

ok(system("killall -w $daemon_name") == 0, "Killed the test daemon");
ok(unlink($conf_name, $log_name, $sock_name, $pidf_name, 
          "$optin_dir/root",
          $ip_whitelistf_name, $rbl_whitelistf_name, $data_name), "Cleaned up");
ok(rmdir($optin_dir), "Removed $optin_dir");
exit;
