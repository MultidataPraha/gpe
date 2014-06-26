#!/exlibris/aleph/a22_1/product/bin/perl

###########################################################
#
# (c) 2013, 2014 MULTIDATA Praha spol. s r.o.
#
# gpe-check.pl 20140626 aleph - gpe interface (dev)
#
###########################################################

use strict;
use warnings;
use diagnostics;
use utf8;
binmode STDOUT, ":utf8";
use CGI;
use File::Basename;

use Crypt::OpenSSL::RSA;

use File::Slurp;
use MIME::Base64;
use DBI;

use POSIX qw(strftime);
use Time::HiRes q/gettimeofday/;

use Getopt::Long;
use SOAP::Lite;

my $script_name = basename( $0, ".pl" );

######################################################################
#
#

my %config;
my %req;
my %resp;

die "missing alephe_tab environment variable" unless $ENV{'alephe_tab'};

my $config_file = $ENV{'alephe_tab'} . '/' . $script_name . '.cfg';

die "cannot open config file $config_file: $!"
    unless read_config($config_file);

my $gpe_ws_url       = $config{'gpe_ws_url'};
my $private_key_file = $config{'gpe_private_key'};
my $public_key_file  = $config{'gpe_public_key'};

$ENV{'aleph_db'}    = $config{'aleph_db'}    if $config{'aleph_db'};
$ENV{'ORACLE_SID'}  = $config{'ORACLE_SID'}  if defined $config{'ORACLE_SID'};
$ENV{'ORACLE_HOME'} = $config{'ORACLE_HOME'} if $config{'ORACLE_HOME'};
$ENV{'LOGDIR'}      = $config{'LOGDIR'}      if $config{'LOGDIR'};
die "missing LOGDIR cfg / env" unless $ENV{'LOGDIR'};
$ENV{'NLS_LANG'} = $config{'NLS_LANG'} if $config{'NLS_LANG'};
$ENV{'NLS_LANG'} = 'American_America.UTF8' unless $ENV{'NLS_LANG'};

$config{'Z31_PAYMENT_MODE'} = substr( $config{'Z31_PAYMENT_MODE'}, 0, 2 )
    if $config{'Z31_PAYMENT_MODE'};

my ( $dbh, $sql, $sth );

my $adm_library;

my $usr_library = $config{'usr_library'};

my $soap_response_result;

my $z31_status;

my $logfile;

my $current_timestamp;

eval {
    my $logfile_name = $ENV{"LOGDIR"} . '/' . $script_name . '.log';
    open( $logfile, ">>", $logfile_name )
        || die "cannot write log: $logfile_name: $!";
    die "missing aleph_db / ORACLE_SID cfg / env"
        unless $ENV{'aleph_db'} || $ENV{'ORACLE_SID'};
    die "missing ORACLE_HOME cfg / env" unless $ENV{'ORACLE_HOME'};

    binmode( $logfile, ":unix" );

    #    open( STDERR, ">&", $logfile );
    my $connect_string;
    $connect_string = "dbi:Oracle:$ENV{'aleph_db'}" unless $ENV{'ORACLE_SID'};
    $connect_string = "dbi:Oracle:"
        if $ENV{'ORACLE_SID'};

    $dbh = DBI->connect( "$connect_string", 'aleph', 'aleph',
        { RaiseError => 1, PrintError => 1, AutoCommit => 0, Warn => 1 } );

    GetOptions( "adm=s" => \$adm_library ) or die "missing --adm XXX50";
    check_libs();

    my $last_ordernumber = last_ordernumber();
    $current_timestamp = get_time_stamp_15();
    update_z31();

    for ( my $i = first_ordernumber(); $i <= $last_ordernumber; $i++ ) {

        #        chomp;
        #        $req{'ORDERNUMBER'} = $_;
        $req{'ORDERNUMBER'} = $i;

        get_soap_response();

        get_z31();
        my $log_line = sprintf(
            "%s|%s|%s|%s|%s|%s|",
            $soap_response_result->{'orderNumber'},
            $soap_response_result->{'state'},
            $soap_response_result->{'ok'},
            $soap_response_result->{'primaryReturnCode'},
            $soap_response_result->{'secondaryReturnCode'},

            #            $soap_response_result->{'requestId'},
            $z31_status
        );
        write_log("CHK|$log_line");
        if (   ( $soap_response_result->{'state'} =~ /^[78]$/ )
            && ( $z31_status !~ /^C$/ ) )
        {
            write_log("ERR|$log_line");
            printf STDERR ("ERR|$log_line\n");
        }
    }
    $dbh->commit;

    exit;
#########################################################################################

} or do {

#########################################################################################

    $@ = "unknown error" unless $@;
    chomp $@;
    $@ =~ s/\n/#/g;
    write_log($@);
};

exit;

sub append_escape {
    my ( $key, $value ) = @_;
    return join( '=', $key, uri_escape($value) );
}

sub get_time3 {
    my ( $seconds, $microseconds ) = gettimeofday;
    return strftime( q/%FT%T/, localtime($seconds) )
        . sprintf( ".%03d", $microseconds / 1000 );
}

sub get_time_stamp_15 {
    my ( $seconds, $microseconds ) = gettimeofday;
    return strftime( q/%Y%m%d%H%M%S/, localtime($seconds) )
        . sprintf( "%1.1u", $microseconds / 100000 );
} ## end sub get_time_stamp_15

sub read_config {
    my $cfg_file_name = shift;

    open my $cfg_file, "<", $cfg_file_name || die "$!";
    while (<$cfg_file>) {
        if (/^[;!\#]/) {
            next;
        }
        if (/^\s*([a-z][a-z0-9_]*)\s*=\s*(.*?)\s*$/i) {
            $config{ ($1) } = $2;
        }
    } ## end while (<IN>)
    close $cfg_file;
} ## end sub read_config

sub write_debug {
    write_log( "debug: " . shift(@_) ) if $config{'debug'};
}

sub write_log {
    print $logfile get_time3(), " ", shift(@_), "\n"
        || die "cannot write log: $!";
}

sub check_libs {

    $sql = <<"EOT";
       select * FROM ${adm_library}.z31 where 1 = 0
EOT

    my $print_error = $dbh->{PrintError};
    $dbh->{PrintError} = 0;

    eval {

        $sth = $dbh->prepare($sql);
        $sth->execute();
    } or die "ADM base not found";

    $dbh->{PrintError} = $print_error;

}

sub create_digest {

    my $text        = shift;
    my $private_key = read_file( $ENV{"alephe_tab"} . "/$private_key_file" )
        || die "cannot read private key: $!";
    my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key($private_key)
        || die "$!";

    my $signature = $rsa_priv->sign($text) || die "$!";
    $req{'DIGEST'} = encode_base64($signature) || die "$!";
    $req{'DIGEST'} =~ s/\n//g;
}

sub check_digest {

    my $text       = shift;
    my $key_string = read_file( $ENV{"alephe_tab"} . "/$public_key_file" );
    my $rsa_pub    = Crypt::OpenSSL::RSA->new_public_key($key_string);
    my $signature  = decode_base64( $resp{'DIGEST'} );

    die "signature error" unless $rsa_pub->verify( $text, $signature );
    write_debug("signature ok");

}

sub get_soap_response {

    my $soap_op = "queryOrderState";
    create_digest( $config{'MERCHANTNUMBER'} . "|" . $req{'ORDERNUMBER'} );
    my $soap_response
        = SOAP::Lite->proxy( $gpe_ws_url, timeout => 20 )->$soap_op(
        SOAP::Data->type('xsd:string')
            ->name( merchantNumber => $config{'MERCHANTNUMBER'} ),
        SOAP::Data->type('xsd:string')
            ->name( orderNumber => $req{'ORDERNUMBER'} ),
        SOAP::Data->type('xsd:string')->name( digest => $req{'DIGEST'} )
        );

    $soap_response_result = $soap_response->result;
    $resp{'DIGEST'} = $soap_response_result->{digest};
    check_digest( $req{'ORDERNUMBER'} . "|"
            . $soap_response_result->{'state'} . "|"
            . $soap_response_result->{'primaryReturnCode'} . "|"
            . $soap_response_result->{'secondaryReturnCode'} );

}

sub update_z31 {

    $sql = <<"EOT";
       update ${adm_library}.z31 set Z31_PAYMENT_RECEIPT_NUMBER = ?
       where Z31_PAYMENT_IDENTIFIER like 'GPE-%'
       and Z31_PAYMENT_RECEIPT_NUMBER is NULL
EOT

    $sth = $dbh->prepare($sql);
    $sth->execute($current_timestamp);

}

sub get_z31 {

    $sql = <<"EOT";
       select /*+ DYNAMIC_SAMPLING(2) ALL_ROWS */ cast(nvl(wm_concat(distinct Z31_STATUS),'NULL') as varchar(100))
       from ${adm_library}.z31
       where
       (Z31_PAYMENT_IDENTIFIER = 'GPE-'||?
           or Z31_PAYMENT_IDENTIFIER like 'GPE-'||?||'-%')
       and Z31_PAYMENT_RECEIPT_NUMBER = ?
EOT

    $sth = $dbh->prepare($sql);
    $sth->execute( $req{'ORDERNUMBER'}, $req{'ORDERNUMBER'},
        $current_timestamp );
    ($z31_status) = $sth->fetchrow_array();

}

sub first_ordernumber {
    $sql = <<"EOT";
       select /*+ DYNAMIC_SAMPLING(2) ALL_ROWS */ min(x)
       from
       (select regexp_replace(Z31_PAYMENT_IDENTIFIER,'GPE-([0-9]*).*','\\1')+0 x
         from ${adm_library}.z31
         where regexp_like(Z31_PAYMENT_IDENTIFIER,'GPE-[0-9]')
         and Z31_PAYMENT_RECEIPT_NUMBER = ?
       union select Z52_SEQUENCE+1 x
         from ${usr_library}.z52
         where Z52_REC_KEY = 'last-gpe-order-no')
EOT

    $sth = $dbh->prepare($sql);
    $sth->execute($current_timestamp);
    ( my $result ) = $sth->fetchrow_array();
    write_debug("first_ordernumber: $result");
    return $result;
}

sub last_ordernumber {
    $sql = <<"EOT";
       select /*+ DYNAMIC_SAMPLING(2) ALL_ROWS */ Z52_SEQUENCE
       from ${usr_library}.z52
       where Z52_REC_KEY = 'last-gpe-order-no'
EOT

    $sth = $dbh->prepare($sql);
    $sth->execute();
    ( my $result ) = $sth->fetchrow_array();
    write_debug("last_ordernumber: $result");
    return $result;
}

#sub get_z31 {
#
#    $sql = <<"EOT";
#       select /*+ DYNAMIC_SAMPLING(2) ALL_ROWS */ cast(nvl(wm_concat(distinct Z31_STATUS),'NULL') as varchar(100))
#       from ${adm_library}.z31
#       where Z31_PAYMENT_IDENTIFIER = 'GPE-'||?
#       or Z31_PAYMENT_IDENTIFIER like 'GPE-'||?||'-%'
#EOT
#
#    $sth = $dbh->prepare($sql);
#    $sth->execute( $req{'ORDERNUMBER'}, $req{'ORDERNUMBER'}, $current_timestamp );
#    ($z31_status) = $sth->fetchrow_array();
#
#}

#sub first_ordernumber {
#    $sql = <<"EOT";
#       select /*+ DYNAMIC_SAMPLING(2) ALL_ROWS */ max(regexp_replace(Z31_PAYMENT_IDENTIFIER,'GPE-([^-]*)(-.*)*','\\1'))
#       from ${adm_library}.z31
#       where Z31_PAYMENT_IDENTIFIER like 'GPE-%'
#       and Z31_DATE_X < to_char(sysdate-8,'YYYYMMDD')
#EOT
#
#    $sth = $dbh->prepare($sql);
#    $sth->execute();
#    ( my $result ) = $sth->fetchrow_array();
#    write_debug("first_ordernumber: $result");
#    return $result;
#}
#
#sub last_ordernumber {
#    $sql = <<"EOT";
#       select /*+ DYNAMIC_SAMPLING(2) ALL_ROWS */ Z52_SEQUENCE
#       from ${usr_library}.z52
#       where Z52_REC_KEY = 'last-gpe-order-no'
#EOT
#
#    $sth = $dbh->prepare($sql);
#    $sth->execute();
#    ( my $result ) = $sth->fetchrow_array();
#    write_debug("last_ordernumber: $result");
#    return $result;
#}

