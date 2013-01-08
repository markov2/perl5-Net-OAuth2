package Net::OAuth2::Profile::WebServer;
use base 'Net::OAuth2::Profile';

use warnings;
use strict;

use Net::OAuth2::AccessToken;
use MIME::Base64  'encode_base64';
use Scalar::Util  'blessed';

use HTTP::Request     ();
use HTTP::Response    ();
use HTTP::Status      qw(HTTP_TEMPORARY_REDIRECT);

=chapter NAME
Net::OAuth2::Profile::WebServer - OAuth2 for web-server use

=chapter SYNOPSIS

  my $auth = Net::OAuth2::Profile::WebServer->new
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

  # Let user ask for a grant from the resource owner
  print $auth->authorize_response->as_string;
  # or, in Plack:   redirect $auth->authorize;

  # Prove your identity at the authorization server
  my $access_token  = $auth->get_access_token($info->{code});

  # communicate with the resource serve
  my $response      = $access_token->get('/me');
  $response->is_success
      or die "error: " . $response->status_line;

  print "Yay, it worked: " . $response->decoded_content;


=chapter DESCRIPTION
Use OAuth2 in a WebServer context.  Read the DETAILS section, far below
this man-page before you start implementing this interface.

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
=section Actions

=method authorize OPTIONS
On initial contact of a new user, you have to redirect to the resource
owner.  Somewhere in the near future, your application will be contacted
again by the same user but then with an authorization grant code.

Only the most common OPTIONS are listed... there may be more: read the
docs on what your server expects.

=option  state STRING
=default state C<undef>

=option  scope STRING
=default scope C<undef>

=option  client_id STRING
=default client_id M<new(client_id)>

=option  response_type STRING
=default response_type 'code'

=example
  my $auth = Net::OAuth2::Profile::WebServer->new(...);

  # From the Plack demo, included in this distribution (on CPAN)
  get '/get' => sub { redirect $auth->authorize };

  # In generic HTTP, see method authorize_response
  use HTTP::Status 'HTTP_TEMPORARY_REDIRECT';   # 307
  print HTTP::Response->new
    ( HTTP_TEMPORARY_REDIRECT => 'Get authorization grant'
    , [ Location => $auth->authorize ]
    )->as_string;
=cut

sub authorize(@)
{   my ($self, @req_params) = @_;

    # temporary, for backward compatibility warning
    my $uri_base = $self->SUPER::authorize_url;
#   my $uri_base = $self->authorize_url;

    my $uri      = blessed $uri_base && $uri_base->isa('URI')
      ? $uri_base->clone : URI->new($uri_base);

    my $params   = $self->authorize_params(@req_params);
    $uri->query_form($uri->query_form, %$params);
    $uri;
}

# Net::OAuth2 returned the url+params here, but this should return the
# accessor to the parameter with this name.  The internals of that code
# was so confused that it filled-in the params multiple times.
sub authorize_url()
{   require Carp;
    Carp::confess("do not use authorize_url() but authorize()! (since v0.50)");
}

=method authorize_response [REQUEST]
Convenience wrapper around M<authorize()>, to produce a complete
M<HTTP::Response> object to be sent back.
=cut

sub authorize_response(;$)
{   my ($self, $request) = @_;
    my $resp = HTTP::Response->new
      ( HTTP_TEMPORARY_REDIRECT => 'Get authorization grant'
      , [ Location => $self->authorize ]
      );
    $resp->request($request) if $request;
    $resp;
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

    # should not be required: usually the related between client_id and
    # redirect_uri is fixed to avoid security issues.
    my $r = $self->redirect_uri;
    $params->{redirect_uri}  ||= $r if $r;

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

#--------------------
=chapter DETAILS

=section The process

The B<main complication> does not show in the example in the SYNOPSIS,
not in the plack example included in the distribution: your client session
can not survive the shown steps: your application behaves like a server,
not a client.  You need to implement losely coupled server-server
communication, which is less straight-forward.

First, your application must implement a persistent session (in a database
or file), which may get called on any weird moment to pass on information.
Your application must be visible from "outside" and use https.  More than
enough complications.  Full example needed ;-)

The client side of the process has
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
=cut

1;
