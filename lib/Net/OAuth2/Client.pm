package Net::OAuth2::Client;
use warnings;
use strict;

use LWP::UserAgent ();
use URI            ();
use JSON           qw/decode_json/;

use Net::OAuth2::Profile::WebServer;
use Net::OAuth2::Profile::Password;

=chapter NAME
Net::OAuth2::Client - client for OAuth2 access, deprecated interface

=chapter SYNOPSIS

   # This module provides the deprecated interface
   my $client = Net::OAuth2::Client->new(
       $client_id,
       $client_secret,
       site => $site
   );

   my $auth = $client->web_server(
       redirect_path => "$site/auth/facebook/callback"
   );

   # interface since v0.50
   my $client = Net::OAuth2::Profile::WebServer->new(
       client_id     => $client_id,
       client_secret => $client_secret,
       site          => $site
       redirect_uri  => "$site/auth/facebook/callback"
   );

=chapter DESCRIPTION
This module is kept to translate the expired interface into the new
interface.

=chapter METHODS

=section Constructors

=c_method new ID, SECRET, OPTIONS
This object collects all OPTIONS to be used when M<web_server()> creates
a profile.

The ID will be translated into OPTION C<client_id>, and SECRET to
C<client_secret>.
=cut

sub new($$@)
{   my ($class, $id, $secret, %opts) = @_;

    $opts{client_id}     = $id;
    $opts{client_secret} = $secret;

    # auto-shared user-agent
    $opts{user_agent}  ||= LWP::UserAgent->new;

    bless \%opts, $class;
}

#----------------
=section Accessors
=method id
=method secret
=method user_agent
=cut

sub id()         {shift->{NOC_id}}
sub secret()     {shift->{NOC_secret}}
sub user_agent() {shift->{NOC_agent}}

#----------------
=section Actions

=method web_server OPTIONS
Create a M<Net::OAuth2::Profile::WebServer> object, based on all options
passed with M<new()>, overruled/extended by the OPTIONS passed here.
=cut

sub web_server(@)
{   my $self = shift;
    Net::OAuth2::Profile::WebServer->new(%$self, @_);
}


=method password OPTIONS
Create a M<Net::OAuth2::Profile::Password> object, based on all options
passed with M<new()>, overruled/extended by the OPTIONS passed here.
=cut

sub password(@)
{   my $self = shift;
    Net::OAuth2::Profile::Password->new(%$self, @_);
}

1;
