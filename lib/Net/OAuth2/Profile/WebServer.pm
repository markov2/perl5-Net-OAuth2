package Net::OAuth2::Profile::WebServer;
use base 'Net::OAuth2::Profile';

use warnings;
use strict;

use Net::OAuth2::AccessToken;
use HTTP::Request;
use MIME::Base64  'encode_base64';

=chapter NAME
Net::OAuth2::Profile::WebServer - OAuth2 for web-server use

=chapter SYNOPSIS

  my $google = Net::OAuth2::Profile::WebServer->new
    ( name           => 'Google Contacts'
    , client_id      => $id
    , client_secret  => $secret
    , site           => 'https://accounts.google.com'
    , scope          => 'https://www.google.com/m8/feeds/'
    , authorize_path    => '/o/oauth2/auth'
    , access_token_path => '/o/oauth2/token'
    , protected_resource_url
        =>  'https://www.google.com/m8/feeds/contacts/default/full'
    );

=chapter DESCRIPTION
Use OAuth2 in a WebServer context.  The client side of the process has
three steps, nicely described in
L<https://tools.ietf.org/html/rfc6749|RFC6749>

=over 4
=item 1. Send an authorization request to resource owner
It needs a C<client_id>: usually the name of the service where you want
get access to.  The answer is a redirect, based on the C<redirection_uri>
which you usually pass on.  Additional C<scope> and C<state> parameters
can be needed or useful.  The redirect will provide you with (amongst other
things) a C<code> parameter.

=item 2. Translate the code into an access token
With the code, you go to an authorization server which will validate
your existence.  An access token (and sometimes a refresh token) are
returned.

=item 3. Address the protected resource
The access token, usually a 'bearer' token, is added to each request to
the resource you want to address.  The token may refresh itself when
needed.
=back

=chapter METHODS

=section Constructors

=c_method new OPTIONS

=option  redirect_uri URI
=default redirect_uri C<undef>

=option  referer      URI
=default referer      C<undef>
Adds a C<Referer> header to each request.  Some servers check whether
provided redirection uris point to the same server the page where the
link was found.

=default grant_type 'authorization_code'
=cut

sub init($)
{   my ($self, $args) = @_;
    $args->{grant_type}  ||= 'authorization_code';
    $self->SUPER::init($args);
    $self->{NOPW_redirect} = $args->{redirect_uri};
    $self->{NOPW_referer}  = $args->{referer};
    $self;
}

#-------------------
=section Accessors

=method redirect_uri
=method referer [URI]
=cut

sub redirect_uri() {shift->{NOPW_redirect}}
sub referer(;$)
{   my $s = shift; @_ ? $s->{NOPW_referer} = shift : $s->{NOPW_referer} }

#--------------------
=section Action

=method authorize OPTIONS
Request an authorization code for the session.  Only the most common
OPTIONS are listed... there may be more: read the docs on what your
server expects.

=option  state STRING
=default state C<undef>

=option  scope STRING
=default scope C<undef>

=option  client_id STRING
=default client_id M<new(client_id)>

=option  response_type STRING
=default response_type 'code'
=cut

sub authorize(@)
{   my ($self, @req_params) = @_;
    my $request = $self->build_request
      ( $self->authorize_method
      , $self->authorize_url
      , $self->authorize_params(@req_params)
      );

    my $ua        = $self->user_agent;
    my $old_redir = $ua->requests_redirectable;
    $ua->requests_redirectable([]);

    my $response  = $self->request($request);

    $ua->requests_redirectable($old_redir);
    $response;
}

=method get_access_token CODE, OPTIONS

=option  client_id STRING
=default client_id M<new(client_id)>

=option  client_secret STRING
=default client_secret M<new(client_secret)>
=cut

sub get_access_token($@)
{   my ($self, $code, @req_params) = @_;

    # rfc6749 section "2.3.1. Client Password"
    # header is always supported, client_id/client_secret may be.  We do both.
    my $params  = $self->access_token_params(code => $code, @req_params);
    my $request = $self->build_request
      ( $self->access_token_method
      , $self->access_token_url
      , $params
      );
    my $basic = encode_base64 "$params->{client_id}:$params->{client_secret}";
    $request->headers->header(Authorization => "Basic $basic");
    my $response = $self->request($request);

    Net::OAuth2::AccessToken->new(client => $self
      , $self->params_from_response($response, 'access token'));
}

=method update_access_token TOKEN, OPTIONS
Ask the server for a new token.  You may pass additional OPTIONS as
pairs.  However, this method is often triggered automatically, in which
case you can to use the C<refresh_token_params> option of M<new()>.

=examples
  $auth->update_access_token($token);
  $token->refresh;   # nicer
=cut

sub update_access_token($@)
{   my ($self, $access, @req_params) = @_;
    my $refresh =  $access->refresh_token
        or die 'unable to refresh token without refresh_token';

    my $req   = $self->build_request
      ( $self->refresh_token_method
      , $self->refresh_token_url
      , $self->refresh_token_params(refresh_token => $refresh, @req_params)
      );

    my $resp  = $self->request($req);
    my $data  = $self->params_from_response($resp, 'update token');

    my $token = $data->{access_token}
        or die "no access token found in refresh data";

    my $type  = $data->{token_type};

    my $exp   = $data->{expires_in}
        or die  "no expires_in found in refresh data";

    $access->update_token($token, $type, $exp+time());
}

sub authorize_params(%)
{   my $self   = shift;
    my $params = $self->SUPER::authorize_params(@_);
    $params->{response_type} ||= 'code';
    $params->{redirect_uri}  ||= $self->redirect_uri;
    $params;
}

sub access_token_params(%)
{   my $self   = shift;
    my $params = $self->SUPER::access_token_params(@_);
    $params->{redirect_uri} ||= $self->redirect_uri;
    $params;
}

sub refresh_token_params(%)
{   my $self   = shift;
    my $params = $self->SUPER::refresh_token_params(@_);
    $params->{grant_type}   ||= 'refresh_token';
    $params;
}

#--------------------
=section Helpers
=cut

sub build_request($$$)
{   my $self    = shift;
    my $request = $self->SUPER::build_request(@_);

    if(my $r = $self->referer)
    {   $request->header(Referer => $r);
    }

    $request;
}

1;
