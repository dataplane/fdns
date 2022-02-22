#!/usr/bin/perl -T
use strict;
use warnings;

use File::Basename;
use Getopt::Std;
use Math::BigInt;
use Net::DNS::Nameserver;
use Net::IP;
use POSIX qw( setsid );
use Sys::Syslog qw( :standard :macros );

use constant LISTENER_PORT   => 53;
use constant MAX_LISTENERS   => 32;

use constant SYSLOG_FACILITY => 'LOG_LOCAL0';
use constant SYSLOG_IDENT    => 'fdnsd';
use constant SYSLOG_PRIORITY => 'LOG_INFO';
use constant SYSLOG_SERVER   => '127.0.0.1';

use constant PID_FILE => '/var/run/fdnsd.pid';

use constant USAGE => "usage: $0 [-h] [-d] [-i ipaddrs_file] [-l port] [-p pidfile]
        -h: this message
        -d: enable debugging mode (do not daemonize)
        -i: file list of addresses to listener on (default = ::)
        -l: listener port (default=" . LISTENER_PORT . ")
        -p: pidfile (default=" . PID_FILE . ")\n";

local $SIG{CHLD} = 'IGNORE';    # to avoid having defunct children around

$|++;    # autoflush

getopts( 'hdi:l:p:', \my %opts );
die USAGE if $opts{h};

my $pidfile = $opts{p} || PID_FILE;

# try to safely use pidfile with taint mode
$pidfile = $pidfile =~ m{ \A ( [\w\/\.-]+ ) \z }xms ? $1 : undef;
if ( not defined $pidfile ) {
    die "Unexpected characters in pidfile: $pidfile";
}
my $base_dir = dirname $pidfile;
if ( ! -w $base_dir ) {
    die "Can't write to base directory: $base_dir";
}
if ( -e $pidfile && ! -w $pidfile ) {
    die "existing pidfile not writeable; $pidfile";
}

my $dport = $opts{l} || LISTENER_PORT;
$dport = $dport =~ m{ \A (\d{1,5}) \z }xms ? $1 : undef;
die '-p dport setting invalid'      if ! $dport;
die '-p dport setting out of range' if $dport < 1 || $dport > 65535;
die 'root privs required'           if $dport < 1024 && $> != 0;

my @localaddrs = '::';
# It would be is easier to have a single socket listener, but
# Perl's UDP socket handling doesn't track local addresses we'd
# like to reply from and log when socket is bound with INADDR_ANY
# or INADDR6_ANY. Provide file list of addresses to overcome this.
# This will create a socket listener for each address.
if ($opts{i}) {
    @localaddrs = read_localaddrs_file();
}

daemonize() if ! $opts{d};
my $pid = $$;
create_pid();
local $SIG{TERM} = \&terminate if ! $opts{d};

# initialize syslog
$Sys::Syslog::host = SYSLOG_SERVER;
openlog( SYSLOG_IDENT, "nodelay,pid", SYSLOG_FACILITY );

logit({ message => "Listener addresses: " . join ', ', @localaddrs });

my $ns = Net::DNS::Nameserver->new(
    LocalAddr    => [@localaddrs],
    LocalPort    => $dport,
    ReplyHandler => \&reply_handler,
    Verbose      => $opts{d} ? 1 : 0,
) || die "Could not create nameserver object";

$ns->main_loop;

terminate() if ! $opts{d};
exit 0;

sub read_localaddrs_file {
    open( my $LOCALADDRS_FILE, '<', $opts{i} )
        or die "Unable to open $opts{i}: $!";

    my @localaddrs;

    while ( defined (my $line=<$LOCALADDRS_FILE>) ) {
        chomp $line;

        $line =~ s{ \A \s* }{}xms;
        $line =~ s{ \s* \z }{}xms;
        $line =~ s{ \s* [#] .* \z }{}xms;

        # skip blank lines or comments
        next if $line =~ m{ \A \s* (?: [#] .* )? \z }xms;

        # use Net::IP to perform IP address sanity checking, skip on failure
        my $ip = new Net::IP($line) || next;
        next if $ip->size() != 1;
        # hack to untaint, which should be safe now
        my ($addr) = $line =~ m{ \A (.*) \z }xms;
        push @localaddrs, $addr;
    }
    # fall back to INADDR6_ANY if we exceed socket limit
    return scalar @localaddrs > MAX_LISTENERS ? '::' : @localaddrs;
}

# http://stackoverflow.com/questions/1518923/how-can-i-create-a-tcp-server-daemon-process-in-perl
sub daemonize {
    chdir '/' or die "Can't chdir to /: $!";
    open STDIN, '<', '/dev/null'  or die "Can't read /dev/null: $!";
    open STDOUT, '>', '/dev/null' or die "Can't write to /dev/null: $!";
    defined( my $_pid = fork ) or die "Can't fork: $!";
    exit if $_pid;
    setsid or die "Can't start a new session: $!";
    open STDERR, '>&STDOUT' or die "Can't dup stdout: $!";
    return;
}

sub create_pid {
    my $_pid = $$;
    open my $fd, '>', $pidfile or die "Can't write $pidfile: $!";
    print $fd $_pid;
    close $fd or die "Can't close $pidfile: $!";
    return;
}

sub terminate {
    if ( $$ == $pid ) {
        close $ns;
        closelog();
        unlink $pidfile or die "Can't remove $pidfile: $!";
    }

    return;
}

sub logit {
    my ($arg_ref) = @_;
    my $priority = $arg_ref->{priority} || SYSLOG_PRIORITY;
    my $message = $arg_ref->{message} or return;

    if ($opts{d}) {
        print STDERR "$message\n";
    }
    else {
        syslog( $priority, "%s", $message );
    }

    return;
}

# check for an IPv6 V4MAPPED address and convert to dotted quad if found
sub v4mapped {
    my $addr = shift or return;
    $addr =~ s{ \A ::ffff: }{}ixms;
    return $addr;
}

sub reply_handler {
    my ( $qname, $qclass, $qtype, $peerhost, $query, $conn ) = @_;
    my ( $rcode, @ans, @auth, @add );

    # transform IPV4MAPPED if INADDR6_ANY socket enabled and peer is v4
    my $daddr = v4mapped( $conn->{'sockhost'} );
    my $saddr = v4mapped($peerhost);

    # https://www.net-dns.org/docs/Net/DNS/Header.html
    my @header_fields = (
        $query->header->id,
        $query->header->qr,
        $query->header->opcode,
        $query->header->aa,
        $query->header->tc,
        $query->header->rd,
        $query->header->ra,
        $query->header->z,
        $query->header->ad,
        $query->header->cd,
        $query->header->rcode,
        $query->header->qdcount,
        $query->header->ancount,
        $query->header->nscount,
        $query->header->arcount,
        $query->edns->version,
        $query->header->do,
        $query->header->size,
        scalar($query->edns->options),  # just get option count
    );
    my $header = join ',', @header_fields;
 
    logit({ message => "Query: $saddr,$conn->{'peerport'},$daddr,$conn->{'protocol'},$header,$qclass,$qtype,$qname" });

    # if UDP send back a truncated response
    if ( $conn->{'protocol'} == 17 ) {
        return( 'NOERROR', undef, undef, undef, { tc => 1 }, );
    }
    else {
        return('REFUSED');
    }
}
