package Net::OAuth2::AccessToken;
use warnings;
use strict;

our $VERSION;  # to be able to test in devel environment

use JSON        qw/encode_json/;
use URI::Escape qw/uri_escape/;
use Encode      qw/find_encoding/;

# Attributes to be saved to preserve the session.
my @session = qw/access_token token_type refresh_token expires_at
   scope state auto_refresh/;

# This class name is kept for backwards compatibility: a better name
# would have been: Net::OAuth2::Session, with a ::Token::Bearer split-off.

# In the future, most of this functionality will probably need to be
# split-off in a base class ::Token, to be shared with a new extension
# which supports HTTP-MAC tokens as proposed by ietf dragt
#   http://datatracker.ietf.org/doc/draft-ietf-oauth-v2-http-mac/

=chapter NAME
  Net::OAuth2::AccessToken - OAuth2 bearer token

=chapter SYNOPSIS
  my $auth    = Net::OAuth2::Profile::WebServer->new(...);

  my $session = $auth->get_access_token($code, ...);
  # $session is a Net::OAuth2::AccessToken object
  if($session->error)
  {   print $session->error_description;
  }

  my $response = $session->get($request);
  my $response = $session->get($header, $content);
  print $session->to_string;  # JSON

  # probably better to set new(auto_refresh), but you may do:
  $session->refresh if $session->expired;

=chapter DESCRIPTION
This object represents a received (bearer) token, and offers ways to use it
and maintain it.  A better name for this module would include B<client
or session>.

A "bearer token" is an abstract proof of your existence: different
services or potentially different physical servers are able to exchange
information about your session based on this, for instance whether
someone logged-in while showing the token.

=chapter METHODS

=section Constructors

=c_method new %options

=option  expires_at TIMESTAMP
=default expires_at C<undef>
Expire this token after TIMESTAMP (as produced by the time() function)

=option  expires_in SECONDS
=default expires_in C<undef>
Expire the token SECONDS after the initiation of this object.

=requires profile M<Net::OAuth2::Profile> object

=option  access_token STRING
=default access_token C<undef>

=option  refresh_always BOOLEAN
=default refresh_always BOOLEAN
[0.53] Auto-refresh the token at each use.

=option  refresh_token STRING
=default refresh_token C<false>
[0.53] Token which can be used to refresh the token, after it has
expired or earlier.

=option  scope URL
=default scope C<undef>

=option  token_type TYPE
=default token_type C<undef>

=option  changed BOOLEAN
=default changed <false>
[0.52] The token (session) needs to be saved.

=option  auto_refresh BOOLEAN
=default auto_refresh <false>
Refresh the token when expired.

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

    $self->{NOA_expires_at} = $args->{expires_at}
       || ($args->{expires_in} ? time()+$args->{expires_in} : undef);

    # client is the pre-v0.50 name
    my $profile = $self->{NOA_profile} = $args->{profile} || $args->{client}
        or die "::AccessToken needs profile object";

    $self->{NOA_access_token}  = $args->{access_token};
    $self->{NOA_refresh_token} = $args->{refresh_token};
    $self->{NOA_refresh_always}= $args->{refresh_always};
    $self->{NOA_scope}         = $args->{scope};
    $self->{NOA_state}         = $args->{state};
    $self->{NOA_token_type}    = $args->{token_type};
    $self->{NOA_auto_refresh}  = $args->{auto_refresh};
    $self->{NOA_changed}       = $args->{changed};

    $self->{NOA_error}         = $args->{error};
    $self->{NOA_error_uri}     = $args->{error_uri};
    $self->{NOA_error_descr}   = $args->{error_description} || $args->{error};

    $self->{NOA_attr}          = $args;
    $self;
}

=c_method session_thaw $session, %options
Pass in the output of a M<session_freeze()> call in the past (maybe even
for an older version of this module) and get the token object revived. This
$session is a HASH.

You may pass any of the parameters for M<new()> as %options, to overrule
the values inside the $session.

=requires profile M<Net::OAuth2::Profile> object

=example
  my $auth    = Net::OAuth2::Profile::WebServer->new(...);
  my $token   = $auth->get_access_token(...);
  my $session = $token->freeze_session;
  # now save $session in database or file
  ...
  # restore session
  my $auth    = Net::OAuth2::Profile::WebServer->new(...);
  my $token   = Net::OAuth2::AccessToken->session_thaw($session
    , profile => $auth);
=cut

sub session_thaw($%)
{   my ($class, $session) = (shift, shift);
    # we can use $session->{net_oauth2_version} to upgrade the info
    $class->new(%$session, @_);
}

#--------------
=section Accessors

=method token_type 
=method scope 
=method state 
=method profile 
=cut

sub token_type() {shift->{NOA_token_type}}
sub scope()      {shift->{NOA_scope}}
sub state()      {shift->{NOA_state}}
sub profile()    {shift->{NOA_profile}}

=method attribute NAME
[0.58] Sometimes, the token gets attributes which are not standard; they
have no official accessor (yet?).  You can get them with this generic
accessor.
=cut

sub attribute($) { $_[0]->{NOA_attr}{$_[1]} }

=method changed [BOOLEAN]
[0.52] The session (token) needs to be saved, because any of the crucial
parameters have been modified and C<auto_save> is not defined by
the profile.
=cut

sub changed(;$)
{   my $s = shift; @_ ? $s->{NOA_changed} = shift : $s->{NOA_changed} }

=method access_token 
Returns the (base64 encoded version of the) access token.  The token
will get updated first, if it has expired and refresh_token is enabled,
or when M<new(auto_refresh)> is set.

It does not matter that the token is base64 encoded or not: it will
always need to be base64 encoded during transport.
=cut

sub access_token()
{   my $self = shift;

    if($self->expired)
    {   delete $self->{NOA_access_token};
        $self->{NOA_changed} = 1;
        $self->refresh if $self->auto_refresh;
    }
    elsif($self->refresh_always)
    {   $self->refresh;
    }

    $self->{NOA_access_token};
}

#---------------
=subsection errors
When the token is received (hence this object created) it be the
result of an error.  It is the way the original code was designed...

=method error 
=method error_uri 
=method error_description 
=cut

sub error()      {shift->{NOA_error}}
sub error_uri()  {shift->{NOA_error_uri}}
sub error_description() {shift->{NOA_error_descr}}

#---------------
=subsection Expiration

=method refresh_token 
=method refresh_always 
=method auto_refresh 
=cut

sub refresh_token()  {shift->{NOA_refresh_token}}
sub refresh_always() {shift->{NOA_refresh_always}}
sub auto_refresh()   {shift->{NOA_auto_refresh}}

=method expires_at [$timestamp]
Returns the expiration timestamp of this token (true) or C<undef> (false)
when it is not set.
=cut

sub expires_at() { shift->{NOA_expires_at} }

=method expires_in 
Returns the number of seconds left, before the token is expired.  That
may be negative.
=cut

sub expires_in() { shift->expires_at - time() }

=method expired [$after]
Returns true when the token has an expiration set and that time has
passed.  We use this token $after this check: to avoid the token to
timeout inbetween, we take (by default 15 seconds) margin.
=cut

sub expired(;$)
{   my ($self, $after) = @_;
    my $when = $self->expires_at or return;
    $after = 15 unless defined $after;
    $when < time() + $after;
}

=method update_token $token, $tokentype, $expires_at, [$refresh_token]
Change the token.
=cut

sub update_token($$$;$)
{   my ($self, $token, $type, $exp, $refresh) = @_;
    $self->{NOA_access_token}  = $token;
    $self->{NOA_token_type}    = $type if $type;
    $self->{NOA_expires_at}    = $exp;

    $self->{NOA_refresh_token} = $refresh
        if defined $refresh;

    $token;
}

#--------------
=section Actions

=method to_json 
Freeze this object into JSON.  The JSON syntax is also used by the OAuth2
protocol, so a logical choice to provide.  However, generically, the
M<session_freeze()> method provided.
=cut

sub to_json()
{   my $self = shift;
    encode_json $self->session_freeze;
}
*to_string = \&to_json;  # until v0.50

=method session_freeze %options
This returns a SESSION (a flat HASH) containing all token parameters which
needs to be saved to be able to restore this token later.  This SESSION
can be passed to M<session_thaw()> to get revived.

The C<changed> flag will be cleared by this method.

Be sure that your storage is character-set aware.  For instance, you
probably want to set 'mysql_enable_utf8' when you store this in a
MySQL database.  Perl's JSON module will output utf8 by default.
=cut

sub session_freeze(%)
{   my ($self, %args) = @_;
    my %data    = (net_oauth2_version => $VERSION);
    defined $self->{"NOA_$_"} && ($data{$_} = $self->{"NOA_$_"}) for @session;
    $self->changed(0);
    \%data;
}

=method refresh 
Refresh the token, even if it has not expired yet.  Returned is the
new access_token value, which may be undef on failure.
=cut

sub refresh()
{   my $self = shift;
    $self->profile->update_access_token($self);
}

#--------------
=subsection HTTP

The token can be encoded in transport protocol in different ways. Using
these method will add the token to the HTTP messages sent.

=method request $request
=method get $uri, [$header, [$content]]
=method post $uri, [$header, [$content]]
=method delete $uri, [$header, [$content]]
=method put $uri, [$header, [$content]]
=cut

sub request{ my $s = shift; $s->profile->request_auth($s, @_) }
sub get    { my $s = shift; $s->profile->request_auth($s, 'GET',    @_) }
sub post   { my $s = shift; $s->profile->request_auth($s, 'POST',   @_) }
sub delete { my $s = shift; $s->profile->request_auth($s, 'DELETE', @_) }
sub put    { my $s = shift; $s->profile->request_auth($s, 'PUT',    @_) }

1;
