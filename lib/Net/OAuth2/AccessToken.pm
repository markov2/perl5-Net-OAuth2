package Net::OAuth2::AccessToken;
use warnings;
use strict;

use JSON        qw/encode_json/;
use URI::Escape qw/uri_escape/;

# This class name is kept for backwards compatibility: a better name
# would have been: Net::OAuth2::BearerToken

# In the future, most of this functionality will probably need to be
# split-off in a base class ::Token, to be shared with a new extension
# which supports HTTP-MAC tokens as proposed by ietf dragt
#   http://datatracker.ietf.org/doc/draft-ietf-oauth-v2-http-mac/

=chapter NAME
Net::OAuth2::AccessToken - OAuth2 bearer token

=chapter SYNOPSIS
  my $auth  = Net::OAuth2::Profile::WebServer->new(...);

  my $token = $auth->get_access_token($code, ...);
  # $token is a Net::OAuth2::AccessToken
  if($token->error)
  {   print $token->error_description;
  }

  my $response = $token->get($request);
  my $response = $token->get($header, $content);
  print $token->to_string;  # JSON

  # probably better to set new(auto_refresh), but you may do:
  $token->refresh if $token->expired;

=chapter DESCRIPTION
This object represents a received bearer token, and offers ways to use it.

A "bearer token" is an abstract proof of your existence: different
services or potentially different physical servers are able to exchange
information about your session based on this, for instance whether
someone logged-in while showing the token.

=chapter METHODS

=section Constructors

=c_method new OPTIONS

=option  expires_at TIMESTAMP
=default expires_at C<undef>
Expire this token after TIMESTAMP (as produced by the time() function)

=option  expires_in SECONDS
=default expires_in C<undef>
Expire the token SECONDS after the initiation of this object.

=requires profile M<Net::OAuth2::Profile> object

=option  access_token STRING
=default access_token C<undef>

=option  refresh_token BOOLEAN
=default refresh_token C<false>
Auto-refresh the token at each use.

=option  scope URL
=default scope C<undef>

=option  token_type TYPE
=default token_type C<undef>

=option  auto_refresh BOOLEAN
=default auto_refresh <false>
Refresh the token before each use.

=option  error STRING
=default error C<undef>
Set when an error has occured, the token is not valid.  This is not
numerical.

=option  error_description STRING
=default error_description <value of error>
A humanly readible explanation on the error.  This defaults to the
string set with the C<error> option, which is not nice to read.

=option  error_uri URI
=default error_uri C<undef>
Where to find more details about the error.
=cut

sub new(@) { my $class = shift; (bless {}, $class)->init({@_}) }

sub init($)
{   my ($self, $args) = @_;

    $self->{NOA_expires} = $args->{expires_at}
       || ($args->{expires_in} ? time()+$args->{expires_in} : undef);

    # client is the pre-v0.50 name
    my $profile = $self->{NOA_profile} = $args->{profile} || $args->{client}
        or die "accesstoken needs profile object";

    $self->{NOA_token}     = $args->{access_token};
    $self->{NOA_refresh}   = $args->{refresh_token};
    $self->{NOA_scope}     = $args->{scope};
    $self->{NOA_type}      = $args->{token_type};
    $self->{NOA_autofresh} = $args->{auto_refresh};
    $self->{NOA_error}     = $args->{error};
    $self->{NOA_error_uri} = $args->{error_uri};
    $self->{NOA_error_descr} = $args->{error_description} || $args->{error};
    $self;
}

#--------------
=section Accessors

=method refresh_token
=method scope
=method token_type
=method profile
=method auto_refresh
=method error
=method error_uri
=method error_description
=cut

sub refresh_token() {shift->{NOA_refresh}}
sub token_type()    {shift->{NOA_type}}
sub scope()         {shift->{NOA_scope}}
sub profile()       {shift->{NOA_profile}}
sub auto_refresh()  {shift->{NOA_autofresh}}
sub error()         {shift->{NOA_error}}
sub error_uri()     {shift->{NOA_error_uri}}
sub error_description() {shift->{NOA_error_descr}}

=method access_token
Returns the (base64 encoded version of the) access token.  The token
will get updated first, if it has expired and refresh_token is enabled,
or when M<new(auto_refresh)> is set.

It does not matter that the token is base64 encoded or not: it will
always need to be base64 encoded during transport.
=cut

sub access_token()
{   my $self = shift;

    $self->refresh
        if  $self->auto_refresh
        || ($self->refresh_token && $self->expired);

    $self->{NOA_token};
}

=method expires_at [TIMESTAMP]
Returns the expiration timestamp of this token (true) or C<undef> (false)
when it is not set.
=cut

sub expires_at() { shift->{NOA_expires} }

=method expires_in
Returns the number of seconds left, before the token is expired.  That
may be negative.
=cut

sub expires_in() { shift->expires_at - time() }

=method expired [AFTER]
Returns true when the token has an expiration set and that time has
passed.  We use this token AFTER this check: to avoid the token to
timeout inbetween, we take (by default 15 seconds) margin.
=cut

sub expired(;$)
{   my ($self, $after) = @_;
    my $when = $self->expires_at or return;
    $after = 15 unless defined $after;
    $when < time() + $after;
}

=method update_token TOKEN, TOKENTYPE, EXPIRES_AT
Change the token.
=cut

sub update_token($$$)
{   my ($self, $token, $type, $exp) = @_;
    $self->{NOA_token}   = $token;
    $self->{NOA_type}    = $type if $type;
    $self->{NOA_expires} = $exp;
    $token;
}

#--------------
=section Action

=method request REQUEST
=method get    URI, [HEADER, [CONTENT]]
=method post   URI, [HEADER, [CONTENT]]
=method delete URI, [HEADER, [CONTENT]]
=method put    URI, [HEADER, [CONTENT]]
=cut

sub request{ my $s = shift; $s->profile->request_auth($s, @_) }
sub get    { my $s = shift; $s->profile->request_auth($s, 'GET',    @_) }
sub post   { my $s = shift; $s->profile->request_auth($s, 'POST',   @_) }
sub delete { my $s = shift; $s->profile->request_auth($s, 'DELETE', @_) }
sub put    { my $s = shift; $s->profile->request_auth($s, 'PUT',    @_) }

=method to_string
Serialize this object into JSON.
=cut

sub to_string()
{   my $self = shift;
    my %data;
    @data{ qw/access_token token_type refresh_token  expires_at
              scope        state      auto_refresh/ }
  = @$self{qw/NOA_token    NOA_type   NOA_refresh    NOA_expires
              NOA_scope    NOA_state  NOA_autofresh/ };

    encode_json \%data;
}

=method refresh
Refresh the token, even if it has not expired yet.  Returned is the
new access_token value.
=cut

sub refresh()
{   my $self = shift;
    $self->profile->update_access_token($self);
}

1;
