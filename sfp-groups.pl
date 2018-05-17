#!/usr/bin/env perl

use warnings;
use strict;

use lib 'lib';

use SFP::Gapps;
use SFP::Samba4;
use SFP::Standard qw/get_user_input dispatch_calls/;

use Data::Dumper; # Used for debug mode
use Data::Leaf::Walker;
use English;
use Getopt::Std;
use YAML qw/LoadFile/;

# Utility to add or remove users from groups

# Grouptypes are switches that use a specific profile and substitute in
# the command line specified group for the value 'INPUT'. Each such
# profile should have only one leaf node.
# If override is true, it's value will be used instead of a command line
# supplied group name.
# Name is pretty-printable name for error messages
# Type is the profile to be used for that shortcut.  Must be defined in profile file.
# Description is used when generating the scirpt's help message
my %grouptypes = (
    d => { name => 'Disk',    type => 'disk',    override => 0,       description => 'Samba4 disk groups' },
    g => { name => 'Google',  type => 'google',  override => 0,       description => 'Google groups (email aliases)' },
    j => { name => 'Jabber',  type => 'jabber',  override => 0,       description => 'Samba4 jabber groups' },
    l => { name => 'Primary', type => 'primary', override => 0,       description => 'Linux (Samba4) primary groups (*NOT Active Directory primary group!*)' },
    n => { name => 'Network', type => 'network', override => 0,       description => 'Samba4 network groups' },
    N => { name => 'No2Fa',   type => 'google',  override => 'no2fa', description => 'Google No Two Factor Auth group' },
    o => { name => 'Login',   type => 'login',   override => 0,       description => 'Linux (Samba4) login groups' },
    s => { name => 'System',  type => 'system',  override => 0,       description => 'Linux (Samba4) system groups' },
    v => { name => 'VPN',     type => 'network', override => 'vpn',   description => 'VPN access group' },
);

# The keys of the %grouptypes hash can't be sepecifed here, as that'll make for confusing
# command line parsing.
my %options = (
    A => { arg => 1, description => 'Administrator username (defaults to UID)', argname => 'username' },
    a => { arg => 0, description => 'Add specified user to group or profile (default)' },
    D => { arg => 0, description => 'Debug mode' },
    f => { arg => 1, description => 'Profile filename (defaults to \'group-profiles.yaml\')', argname => 'path' },
    F => { arg => 0, description => 'Force reqested action (skips some sanity checks)' },
    L => { arg => 0, description => 'List profiles found in profile file' },
    p => { arg => 1, description => 'Profile to operate on', argname => 'profilename' },
    P => { arg => 1, description => 'Admin user\'s password', argname => 'password', },
    r => { arg => 0, description => 'Remove specified user from group or profile' },
    u => { arg => 1, description => 'Username on which to operate (requred, unless -L)', argname => 'user' },
);

my $PROFILES;  # Reference to the hash of group profiles
my @SERVICES;  # List of services, modules represeting things that have groups
my %opt;       # Options that drive the behavior of the program

my $type_opts  = make_getopt_string({%grouptypes}, sub { not $_[0]->{override} });
my $opt_string = make_getopt_string({%options},    sub { $_[0]->{arg} });
getopts($type_opts . $opt_string, \%opt);

# Debug mode
if ($opt{D}) {
    print STDERR "Parsed these command line options\n";
    print STDERR Dumper \%opt;
}

# We need a user to work on
die help("No username specified") unless $opt{u} or $opt{L};

# Default to add unless mode is specified
unless ($opt{a} or $opt{r}) {
    $opt{a} = 1;
}

# Use default profile file unless overridden
$opt{f} //= 'group-profiles.yaml';
$PROFILES = LoadFile($opt{f});

if ($opt{D}) {
    print STDERR "Loaded these profiles\n";
    print STDERR Dumper $PROFILES;
}

if ($opt{L}) {
    print join "\n", sort keys %$PROFILES;
    print "\n";
    exit(0);
}

# There's no mechanism to process multiple shortcuts in one run,
# so check for and disallow it.
my $num_types = grep { exists $opt{$_} } keys %grouptypes;
if ($num_types > 1) {
    die help("Whoa, cowboy.  One group type at a time, please");
} elsif ($num_types == 1) {
    # Process the single group type
    foreach my $t (keys %grouptypes) {
        # If the grouptype has an override defined, assign that group
        # to the opt hash, so we can process that group normally
        if ($opt{$t} and $grouptypes{$t}->{override}) {
            $opt{$t} = $grouptypes{$t}->{override};
        }
        if (exists $opt{$t} and not defined $opt{$t}) {
            die help("A group name must be supplied with a group type");
        } elsif ($opt{$t}) {
            # We've got a group name, so lets get to work
            populate_profile($grouptypes{$t}->{type}, $opt{$t}, $PROFILES);
            $opt{p} = $grouptypes{$t}->{type};
            if ($opt{D}) {
                print STDERR "Loaded grouptype $t as\n";
                print STDERR Dumper $PROFILES->{$opt{p}};
            }
        }
    }
}

die help("No grouptype or profile to process") unless $opt{p};

unless (exists $opt{p} and exists $PROFILES->{$opt{p}}) {
    die help("The specified profile $opt{p} isn't listed in $opt{f}");
}

# Determine which services we'll need on this run
# inherit ins't a real service and is handled by this script itself.
foreach my $service (keys %{ $PROFILES->{$opt{p}} }) {
    next if $service eq 'inherit';
    push @SERVICES, "SFP::$service";
}

# If we only have Google groups to deal with, set a password so we don't get prompted
if (@SERVICES == 1 && $SERVICES[0] eq 'SFP::Gapps') {
   $opt{P} //= 'BOGUS';
}

my $admin = $opt{A} || getpwuid($REAL_USER_ID);

my %args = (
    gapps_admin    => $opt{A},
    admin          => $admin,
    admin_password => $opt{P} || get_user_input("Samba password for $admin", 1),
    scope          => 'group',      # For Google Apps authentication
    verbose        => $opt{D},
    force          => $opt{F},
    user           => $opt{u},
    groups         => $PROFILES->{$opt{p}},
);

if ($opt{D}) {
    print STDERR "Final options and args before run\n";
    print STDERR Dumper \%opt;
    print STDERR Dumper \%args;
}

dispatch_calls([@SERVICES], {%args}, 'check_auth');

dispatch_profile({%args}, $opt{a} ? 'add_to_groups' : 'remove_from_groups');

# Substitutes the specified group name into the grouptype profile
sub populate_profile {
    my $gt_name  = shift;
    my $group    = shift;
    my $prof_ref = shift;

    die "No profile for $gt_name sortcut type\n" unless $prof_ref->{$gt_name};

    my $w = Data::Leaf::Walker->new($prof_ref->{$gt_name});
    my @keys = $w->keys();

    if (@keys == 1) {
        $w->store( $keys[0], $group );
    } else {
        die "You can only work on one group at a time using shortcuts.\n";
    }

    # Return value is the modified profile reference
}

# Process a group profile
sub dispatch_profile {
    my $args = shift;       # Hashref to arguments
    my $sub  = shift;       # Sub to call in each service module

    my $groups = $args->{groups};

    foreach my $class (keys %$groups) {
        if ($class eq 'inherit') {
            my @profiles = @{ $groups->{$class} };
            foreach my $p (@profiles) {
                $args->{groups} = $PROFILES->{$p};
                dispatch_profile({%$args}, $sub);
            }
        } elsif (grep { "SFP::$class" eq $_ } @SERVICES) {
            no strict 'refs';
            my $sub = "SFP::${class}::${sub}";
            $args->{groups} = $groups->{$class};
            $sub->(%$args);
        } else {
            # Bad profile
            die "Profile $opt{p} in $opt{f} contains invalid group type: $class\n";
        }
    }
}

my %keys = ();
sub make_getopt_string {
    my $config    = shift;
    my $takes_arg = shift;

    my $string = '';
    foreach my $key (keys $config->%*) {
        if ($keys{$key}) {
            die "You can't have the same key $key in grouptypes and options"
        }
        $string .= $key;
        $string .= ':' if $takes_arg->($config->{$key});
        $keys{$key}++;
    }

    return $string;
}

# Sorts alphabetially; AaBbCc etc
sub my_way { lc $a cmp lc $b || $a cmp $b }

sub make_help_string {
    my $config = shift;
    my $format = shift;
    my $parse  = shift;

    my $string;
    foreach my $key (sort my_way keys $config->%*) {
        $string .= sprintf $format, $parse->($key, $config->{$key});
    }

    return $string;
}

sub parse_grouptypes {
    my $k = shift; my $v = shift;
    return '', $k, $v->{description}, $v->{override} ? '*' : '';
}

sub parse_options {
    my $k = shift; my $v = shift;
    return '', $k, $v->{arg} ? '<' . $v->{argname} . '>' : '', $v->{description};
}

sub help {
    my $str;

    if ($_[0]) {
        $str = "$_[0]\n\n";
    } else {
        $str = "\n";
    }

    my $grouptype_string = make_help_string({%grouptypes}, "%8s-%s\t%s %s\n",      \&parse_grouptypes);
    my $option_string    = make_help_string({%options},    "%8s-%s  %-13s   %s\n", \&parse_options);

    $str .= <<EOH;
    $0 -L | -u <username | groupname> [-<grouptype> <groupname> | -p <profilename>] < OPTIONS >

    You must specify -u <username> and one of the group type switches or -p <profilename>
    or -L to list profiles.

    Grounames may be specified in the -u argument to add a group to a group.  In this context, Samba groups
    should be specified as <type>/<groupname>.

    Group types:
$grouptype_string
    Group types need to be specified as -<g> <groupname> unless marked with an '*'
    Any group marked with '*' supplies it's own, non-overriable argument

    Options:
$option_string

    Examples:

    Add the user Fox Mulder to the FBIsLeastWanted disk group.
    $0 -u fmulder -d fbisleastwanted

    Add the user Darth Vader to all the groups in the sith profile, specifying your admin password
    $0 -u dvader -p sith -P !TheDriodsYoureLooking4

    Remove the user Troy McClure from all the groups in the PresidentsNeck profile, as a former admin
    $0 -u tmcclure -r -p presidentsneck -A tdavenport

    Add the itstaff system group to the systems system group
    $0 -u system/itstaff -s systems

    List all the profiles in the additional-profiles.yaml file
    $0 -L -f additional-profiles.yaml

EOH

    return $str;
}
