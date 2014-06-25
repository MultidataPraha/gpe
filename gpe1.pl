#!/exlibris/aleph/a22_1/product/bin/perl

###########################################################
#
# (c) 2013, 2014 MULTIDATA Praha spol. s r.o.
#
# cash-gpe1.pl 20140625 aleph - gpe interface (dev)
#
###########################################################

use strict;
use warnings;
use diagnostics;
use utf8;
binmode STDOUT, ":utf8";
use CGI;

use Crypt::OpenSSL::RSA;
use File::Slurp;
use MIME::Base64;
use DBI;
use URI::Escape;
use POSIX qw(strftime);
use Time::HiRes q/gettimeofday/;
use File::Basename;

my $q = CGI->new;

my %config;
my %param;

die "missing DOCUMENT_ROOT environment variable" unless $ENV{'DOCUMENT_ROOT'};
$ENV{'alephe_tab'} = $ENV{'DOCUMENT_ROOT'} . '/../../tab';

my $script_name;
$script_name = basename( $q->script_name(), ".pl" ) if $q->script_name();
$script_name = basename( $0, ".pl" ) unless $script_name;

my $config_file = $ENV{'alephe_tab'} . '/' . $script_name . '.cfg';

die "cannot open config file $config_file: $!"
    unless read_config($config_file);

$config{'Z31_PAYMENT_MODE'} = substr( $config{'Z31_PAYMENT_MODE'}, 0, 2 )
    if $config{'Z31_PAYMENT_MODE'};

my $usr_library = $config{'usr_library'};
$config{'debug'} = 0 unless defined $config{'debug'};

my $aleph_opac = $config{'aleph_opac'};

my $ignore_digest = $config{'api_ignore_digest'};
$ignore_digest = 0 unless defined $ignore_digest;

my $max_time_diff = $config{'api_max_time_diff'};
$max_time_diff = 300 unless defined $max_time_diff;

# adm_library: Z63_BOR_LIBRARY (Aleph OPAC, aleph_opac=1) / ADM param (API, aleph_opac=0)

my ( $z63_client_address, $z63_bor_id, $adm_library );

my $gpe_url          = $config{'gpe_url'};
my $private_key_file = $config{'gpe_private_key'};
my $public_key_file  = $config{'api_public_key'};
my $opac_err_url     = $config{'opac_err_url'};

my %gpe;

$ENV{'aleph_db'}   = $config{'aleph_db'}   if defined $config{'aleph_db'};
$ENV{'ORACLE_SID'} = $config{'ORACLE_SID'} if defined $config{'ORACLE_SID'};
$ENV{'ORACLE_HOME'} = $config{'ORACLE_HOME'}
    if defined $config{'ORACLE_HOME'};
$ENV{'LOGDIR'} = $config{'LOGDIR'} if defined $config{'LOGDIR'};
die "missing LOGDIR cfg / env" unless $ENV{'LOGDIR'};
$ENV{'NLS_LANG'} = $config{'NLS_LANG'} if defined $config{'NLS_LANG'};
$ENV{'NLS_LANG'} = 'American_America.UTF8' unless $ENV{'NLS_LANG'};

$gpe{'MERCHANTNUMBER'} = $config{'MERCHANTNUMBER'};
$gpe{'OPERATION'}      = 'CREATE_ORDER';
$gpe{'CURRENCY'}       = 203;
$gpe{'URL'}            = $config{'gpe_response_url'};

my $logfile_name = $ENV{"LOGDIR"} . '/' . $script_name . '.log';
open my $logfile, ">>", $logfile_name
    || die "cannot open logfile $logfile_name: $!";

binmode( $logfile, ":unix" );
open STDERR, ">&", $logfile;

my $private_key;
my ( $sql, $sth, $dbh );
my $rv;
my $api_signed_params;

eval {

    die "missing MERCHANTNUMBER cfg" unless defined $gpe{'MERCHANTNUMBER'};
    die "missing aleph_db / ORACLE_SID cfg / env"
        unless $ENV{'aleph_db'} || $ENV{'ORACLE_SID'};
    die "missing ORACLE_HOME cfg / env" unless $ENV{'ORACLE_HOME'};
    my $connect_string;
    $connect_string = "dbi:Oracle:$ENV{'aleph_db'}" unless $ENV{'ORACLE_SID'};
    $connect_string = "dbi:Oracle:" if $ENV{'ORACLE_SID'};
    $dbh = DBI->connect( "$connect_string", 'aleph', 'aleph',
        { RaiseError => 1, AutoCommit => 0, Warn => 1 } );

    $private_key = read_file( $ENV{"alephe_tab"} . "/$private_key_file" )
        || die "cannot read private key";

    $aleph_opac = 1 unless defined $aleph_opac;
    get_id_from_z63() if $aleph_opac;
    get_id_from_params() unless $aleph_opac;

    $sql = <<"EOT";
       update ${usr_library}.z52
       set
         Z52_SEQUENCE = Z52_SEQUENCE + 1
       where Z52_REC_KEY = 'last-gpe-order-no'
       returning Z52_SEQUENCE into :ordernumber
EOT

    $sth = $dbh->prepare($sql);
    $sth->bind_param_inout( ":ordernumber", \$gpe{'ORDERNUMBER'}, 99 );
    $sth->execute;
    $dbh->commit;
    $rv = $sth->rows;
    write_debug( "Z52_SEQUENCE $rv rows @ line " . __LINE__ );

    die
        "no ORDERNUMBER, maybe missing last-gpe-order-no seq in ${usr_library}.z52?"
        unless defined $gpe{'ORDERNUMBER'};

    $sql = <<"EOT";
       update ${adm_library}.z31
       set
         Z31_PAYMENT_IDENTIFIER = 'GPE-'||?,
         Z31_PAYMENT_CATALOGER  = 'GPE1',
         Z31_PAYMENT_MODE       = ?,
         Z31_PAYMENT_IP         = ?
       where Z31_REC_KEY like ? || '%'
       and Z31_STATUS = 'O'
       and Z31_CREDIT_DEBIT = 'D'
       and Z31_SUM > 0
EOT

    $sth = $dbh->prepare($sql);
    $sth->execute(
        $gpe{'ORDERNUMBER'}, $config{'Z31_PAYMENT_MODE'},
        $z63_client_address, $z63_bor_id
    );

    $dbh->commit;
    $rv = $sth->rows;
    write_debug(
        "GPE1, Z31_PAYMENT_*, GPE-$gpe{'ORDERNUMBER'}  $rv rows @ line "
            . __LINE__ );

    $sql = <<"EOT";
       select /*+ DYNAMIC_SAMPLING(2) ALL_ROWS */ sum(Z31_SUM)
       from ${adm_library}.z31
       where Z31_REC_KEY like ? || '%'
       and Z31_STATUS = 'O'
       and Z31_CREDIT_DEBIT = 'D'
       and Z31_PAYMENT_CATALOGER = 'GPE1'
       and Z31_PAYMENT_IDENTIFIER = 'GPE-'||?
EOT

    $sth = $dbh->prepare($sql);
    $sth->execute( $z63_bor_id, $gpe{'ORDERNUMBER'} );

    ( $gpe{'AMOUNT'} ) = $sth->fetchrow_array();

    die "Z31_SUM / AMOUNT = 0, nothing to do, end"
        if ( $gpe{'AMOUNT'} + 0 ) == 0;

    die "aleph AMOUNT $gpe{'AMOUNT'} != param AMOUNT $param{'amount'}"
        unless ( $aleph_opac || ( $gpe{'AMOUNT'} == $param{'amount'} ) );

    $sql = <<"EOT";
       update ${adm_library}.z31
       set
         Z31_PAYMENT_IDENTIFIER = Z31_PAYMENT_IDENTIFIER || '-' || ?
       where Z31_REC_KEY like ? || '%'
       and Z31_STATUS       = 'O'
       and Z31_CREDIT_DEBIT = 'D'
       and Z31_SUM > 0
       and Z31_PAYMENT_IDENTIFIER = 'GPE-' || ?
EOT

    $sth = $dbh->prepare($sql);
    $sth->execute( $gpe{'AMOUNT'}, $z63_bor_id, $gpe{'ORDERNUMBER'} );

    $dbh->commit;
    $rv = $sth->rows;
    write_debug(
        "AMOUNT to Z31_PAYMENT_IDENTIFIER: GPE-$gpe{'ORDERNUMBER'}-$gpe{'AMOUNT'}, $rv @ line "
            . __LINE__ );

    $gpe{'DESCRIPTION'}
        = 'DESCRIPTION ... platba kartou v knihovnim systemu ... tento text bohuzel nikde neni videt ...'
        . $gpe{'ORDERNUMBER'};

    $gpe{'MERORDERNUM'} = $gpe{'ORDERNUMBER'};

    $gpe{'DEPOSITFLAG'} = 1;

    #
    # MD
    #
    $gpe{'MD'}
        = "MD#$z63_bor_id#$gpe{'AMOUNT'}#$adm_library#$z63_client_address#$gpe{'ORDERNUMBER'}";

    my $plaintext;

    $gpe_url = "$gpe_url?" unless $gpe_url =~ /\?$/;

    foreach (
        'MERCHANTNUMBER', 'OPERATION',   'ORDERNUMBER', 'AMOUNT',
        'CURRENCY',       'DEPOSITFLAG', 'MERORDERNUM', 'URL',
        'DESCRIPTION',    'MD'
        )
    {
        $gpe_url .= append_escape( $_, $gpe{$_} ) . '&';

        $plaintext .= "$gpe{$_}|";
    } ## end foreach ('MERCHANTNUMBER', ...)

    $plaintext =~ s/\|$//;

    my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key($private_key)
        || die "$!";

    my $signature = $rsa_priv->sign($plaintext) || die "$!";

    $gpe{'DIGEST'} = encode_base64($signature) || die "$!";

    $gpe{'DIGEST'} =~ s/\n//g;

    $gpe_url .= append_escape( 'DIGEST', $gpe{'DIGEST'} );

    print $q->redirect($gpe_url);
    write_log("OK, redirect to gpe_url: $plaintext");
    write_log(
        "ORDERNUMBER: $gpe{'ORDERNUMBER'}, ADM: $adm_library, AMOUNT: $gpe{'AMOUNT'}, ID: [$z63_bor_id], aleph_opac: $aleph_opac"
    );

    $dbh->disconnect or warn $dbh->errstr;
#########################################################################################
} or do {

    print $q->redirect($opac_err_url);

    $@ = "unknown error" unless $@;
    chomp $@;
    $@ =~ s/\n/#/g;
    my $err_text = "";
    $err_text .= "aleph_opac: $aleph_opac, " if defined $aleph_opac;
    $err_text .= "api_signed_params: $api_signed_params, "
        if defined $api_signed_params;
    $err_text .= "ORDERNUMBER: $gpe{'ORDERNUMBER'}, "
        if defined $gpe{'ORDERNUMBER'};
    $err_text .= "ADM: $adm_library, "      if defined $adm_library;
    $err_text .= "AMOUNT: $gpe{'AMOUNT'}, " if defined $gpe{'AMOUNT'};
    $err_text .= "ID: [$z63_bor_id], "      if defined $z63_bor_id;
    $err_text .= "REMOTE_ADDR: $ENV{'REMOTE_ADDR'}, "
        if defined $ENV{'REMOTE_ADDR'};
    $err_text .= "z63_client_address: $z63_client_address, "
        if defined $z63_client_address;
    write_log("ERROR, redirect to opac_err_url ($err_text): $@");

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

sub read_config {
    my $cfg_file_name = shift;
    open my $cfg_file, "<", $cfg_file_name || return;
    while (<$cfg_file>) {
        if (/^[;!\#]/) {
            next;
        }
        if (/^\s*([a-z][a-z0-9_]*)\s*=\s*(.*?)\s*$/i) {
            $config{ ($1) } = $2;
        }
    }
    close $cfg_file;
} ## end sub read_config

sub write_debug {
    write_log( "debug: " . shift(@_) ) if $config{'debug'};
}

sub write_log {
    print $logfile get_time3(), " ", shift(@_), "\n";
}

sub find_z303_rec_key {

    my $par_id = shift;
    chomp($par_id);

    $sql = <<"EOT";
select count(distinct Z303_REC_KEY)
from ${usr_library}.z303
where trim(Z303_REC_KEY) = ?
EOT

    $sth = $dbh->prepare($sql);
    $sth->execute($par_id);
    my ($rows) = $sth->fetchrow_array();

    if ( $rows != 1 ) {
        die "z303_rec_key not found, count=$rows";
    }

    $sql = <<"EOT";
select distinct Z303_REC_KEY
from ${usr_library}.z303
where trim(Z303_REC_KEY) = ?
EOT

    $sth = $dbh->prepare($sql);
    $sth->execute($par_id);

    my ($z303_rec_key) = $sth->fetchrow_array();
    return $z303_rec_key;

}

sub check_digest {

    my $text       = shift;
    my $key_string = read_file( $ENV{"alephe_tab"} . "/$public_key_file" );
    my $rsa_pub    = Crypt::OpenSSL::RSA->new_public_key($key_string);
    my $signature  = decode_base64( $q->param('DIGEST') );

    die "signature error" unless $rsa_pub->verify( $text, $signature );
}

sub check_time_diff {

    my $time_dif = abs( $param{'time'} - time );

    die "max allowed TIME difference exceeded"
        if $time_dif > $max_time_diff;
}

sub get_and_check_params {

    foreach ( $q->param ) {

        $param{'id'}     = $q->param($_) if /^id$/i;
        $param{'adm'}    = $q->param($_) if /^adm$/i;
        $param{'time'}   = $q->param($_) if /^time$/i;
        $param{'digest'} = $q->param($_) if /^digest$/i;
        $param{'amount'} = $q->param($_) if /^amount$/i;

        #        $param{'amount'} = $q->param($_) if /^amount$/i;

    }

    # mandatory parameters: ID, ADM, TIME, DIGEST

    die "missing ID parameter"   unless defined $param{'id'};
    die "missing ADM parameter"  unless defined $param{'adm'};
    die "missing TIME parameter" unless defined $param{'time'};

    die "missing AMOUNT parameter" unless defined $param{'amount'};
    die "wrong AMOUNT parameter"
        unless $param{'amount'} =~ /^0*[0-9]{1,8}$/;
    $api_signed_params = join( '|',
        $param{'time'}, $param{'id'}, $param{'adm'}, $param{'amount'} );

    $param{'amount'} += 0;

    die "missing DIGEST parameter"
        unless ( defined $param{'digest'} || $ignore_digest );

    $param{'adm'} = uc( $param{'adm'} );
    $param{'id'}  = uc( $param{'id'} );

    die "wrong ADM parameter"
        unless $param{'adm'} =~ /^[A-Z]{3}5[0-9]$/;
    die "wrong ID parameter" unless $param{'id'} =~ /^[A-Z0-9]+ *$/;
    die "wrong TIME parameter"
        unless $param{'time'} =~ /^[0-9]{10}$/;

    check_digest($api_signed_params) unless $ignore_digest;
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
    } or die "ADM base not found\n";

    $sql = <<"EOT";
       select * FROM ${usr_library}.z308 where 1 = 0
EOT

    eval {

        $sth = $dbh->prepare($sql);
        $sth->execute();
    } or die "z308 table not found in usr_library ${usr_library}\n";

    $dbh->{PrintError} = $print_error;
}

sub get_id_from_z63 {
    my ( $referer, $session_id, $referer_host );
    $referer = $q->referer() or die "missing referer";

    if ( $referer =~ /^https?:\/\/([^\/]+)\/F\/([0-9A-Z]{50})-[0-9]+/ ) {
        $session_id   = $2;
        $referer_host = $1;
    }
    else {
        die "missing session_id";
    }
    write_debug("referer $referer");

    $sql = <<"EOT";
       select /*+ DYNAMIC_SAMPLING(2) ALL_ROWS */ Z63_CLIENT_ADDRESS, Z63_BOR_ID, Z63_BOR_LIBRARY
       from vir01.z63
       where Z63_REC_KEY = ?
EOT

    $sth = $dbh->prepare($sql);
    $sth->execute($session_id);

    ( $z63_client_address, $z63_bor_id, $adm_library )
        = $sth->fetchrow_array()
        or die "session_id not found in vir01.z63";
    my $ref_adm_library;
    if ( $referer =~ /^.*&adm_library=([a-zA-Z0-9]{1,5})/ ) {
        $ref_adm_library = $1;
    }

    write_debug(
        "adm_library = $adm_library, referer adm_library = $ref_adm_library"
    );

    if (   ( defined $ref_adm_library )
        && ( uc($ref_adm_library) ne uc($adm_library) ) )
    {
        $adm_library = uc($ref_adm_library);
        write_debug("seting adm_library to ref_adm_library $adm_library");
    }

    $z63_client_address =~ s/\.0+/./g;
    $z63_client_address =~ s/^0+//;
    $z63_bor_id = sprintf( "%-12s", $z63_bor_id );

    if ( $z63_client_address ne $ENV{'REMOTE_ADDR'} ) {
        die
            "z63_client_address = $z63_client_address, REMOTE_ADDR = $ENV{'REMOTE_ADDR'}";
    }
}

sub get_id_from_params {

    get_and_check_params();
    check_time_diff();
    $z63_bor_id         = find_z303_rec_key( $param{'id'} );
    $z63_client_address = $ENV{'REMOTE_ADDR'};

    # cmdline
    $z63_client_address = '' unless $z63_client_address;
    $adm_library = $param{'adm'};
}
