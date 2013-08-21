#!/usr/bin/perl
# Run test cases

die "Must be root to run this test." if $<;

my @tests = <t/*.t>;
my $curtest = 0;
my $tot_fail = 0;

foreach my $test (@tests) {
    $curtest++;
    print "\n\nTest $curtest. $test:\n";
    my $rc = system("/usr/bin/perl", "$test");
    if ($rc >= 255) {
        print "Test died (rc >= 255)";
        $rc = 1;
    }
    else {
        print "Number of failed test statements: $rc\n";
    }
    if ($rc) {
        $tot_fail++;
    }
}

print "\nTotal tests: $curtest\nTotal test cases with failures: $tot_fail\n";
