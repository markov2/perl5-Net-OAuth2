# This code is part of distribution Net-OAuth2.  Meta-POD processed
# with OODoc into POD and HTML manual-pages.  See README.md
# Copyright Mark Overmeer.  Licensed under the same terms as Perl itself.

package Net::OAuth2::Profile;

use warnings;
use strict;

use LWP::UserAgent ();
use URI            ();
use JSON::MaybeXS  qw/decode_json/;
use Carp           qw/confess carp/;
use Scalar::Util   qw/blessed/;
use Encode         qw/encode/;

use constant MIME_URLENC => 'application/x-www-form-urlencoded';

=chapter NAME
Net::OAuth2::Profile - OAuth2 access profiles

=chapter SYNOPSIS

  See Net::OAuth2::Profile::WebServer 
  and Net::OAuth2::Profile::Password 

=chapter DESCRIPTION
Base class for OAuth `profiles'.  Currently implemented:

=over 4
=item * M<Net::OAuth2::Profile::WebServer>
=item * M<Net::OAuth2::Profile::Password>
=back

You may want to use the
L<OAuth2 documentation at Google|https://developers.google.com/accounts/docs/OAuth2WebServer>
to understand the process and the parameters.

=chapter METHODS

=section Constructors

=c_method new %options
Next to the %options listed below, it is possible to provide settings
for each of the <${commands}> C<access_token>, C<protected_resource>,
C<authorize>, and C<refresh_token>.  For each command, you can set

=over 4
=item * ${command}_url => URI|STRING
The absolute uri which needs to be used to be addressed to execute the
C<$command>.  May be specified as M<URI> object or STRING.
=item * ${command}_path => PATH
As previous, but relative to the C<site> option value.
=item * ${command}_method => 'GET'|'POST'
Which method to use for the call (by default POST).
=item * ${command}_param  => []
Additional parameters for the command.
=back

=requires client_id   STRING
=requires client_secret STRING

=option  user_agent  M<LWP::UserAgent> object
=default user_agent  <created internally>

=option  token_scheme SCHEME
=default token_scheme 'auth-header:Bearer'
See M<add_token()> for the supported SCHEMEs.  Scheme C<auth-header> is
probably the only sane default, because that works with any kind of http
requests, where the other options have limited or possible disturbing
application.

Before [0.53], the default was 'auth-header:OAuth'.

Specify the method to submit authenticated requests to the service. By
default, add the access token as a header, such as: "Authorization:
Bearer TOKEN".  Some services require that the header will be different,
i.e. "Authorization: OAuth TOKEN", for which case specify token_scheme
'auth-header:Oauth'.

To add the access token as a uri-parameter: 'uri-query:oauth_token'
(in this case, the parameter name will be oauth_token)
Merge the access token inside a form body via 'form-body:oauth_token'

=option  site URI
=default site C<undef>

=option  scope STRING
=default scope C<undef>

=option  state STRING
=default state C<undef>

=option  hd STRING
=default hd C<undef>
Passthrough parameter that allows you to restrict one's login to a particular
Google Apps domain. The application making the call should check that the
returned value for hd matches the expected domain, as the user can change the
hd parameter in the original request.

See F<https://developers.google.com/identity/protocols/OpenIDConnect#hd-param>
for more details.

=requires grant_type STRING

=option  secrets_in_params BOOLEAN
=default secrets_in_params <true>
The client secrets are passed both via an Authentication header, as via
query parameters in the URI.  The former is required to be accepted by
rfc6749, the latter is optional.  However: many servers use the query
parameters only.

QQ Catalyst, on the other hand, does refuse requests with these parameters
in the query.  So, with this flag explicitly set to false, only the
Auth header gets included.
=cut
# old names still supported:
#   bearer_token_scheme => token_scheme

sub new(@)
{   my $class = shift;
    $class ne __PACKAGE__
        or carp 'you need to create an extension, not base-class '.__PACKAGE__;
    (bless {}, $class)->init( {@_} );
}

# rfc6849 Appendix B, http://www.w3.org/TR/1999/REC-html401-19991224
sub _url_enc($)
{   my $x = encode 'utf8', shift;  # make bytes
    $x =~ s/([^A-Za-z0-9 ])/sprintf("%%%02x", ord $1)/ge;
    $x =~ s/ /+/g;
    $x; 
}

sub init($)
{   my ($self, $args) = @_;
    my $id     = $self->{NOP_id}     = $args->{client_id}
        or carp "profile needs id";
    my $secret = $self->{NOP_secret} = $args->{client_secret}
        or carp "profile needs secret";

    $self->{NOP_id_enc}      = _url_enc $id;
    $self->{NOP_secret_enc}  = _url_enc $secret;

    $self->{NOP_agent}       = $args->{user_agent} || LWP::UserAgent->new;
    $self->{NOP_scheme}      = $args->{token_scheme}
        || $args->{bearer_token_scheme} || 'auth-header:Bearer';
    $self->{NOP_scope}       = $args->{scope};
    $self->{NOP_state}       = $args->{state};
    $self->{NOP_hd}          = $args->{hd};
    $self->{NOP_method}      = $args->{access_token_method} || 'POST';
    $self->{NOP_acc_param}   = $args->{access_token_param} || [];
    $self->{NOP_init_params} = $args->{init_params};
    $self->{NOP_grant_type}  = $args->{grant_type};
    $self->{NOP_show_secret} = exists $args->{secrets_in_params}
      ? $args->{secrets_in_params} : 1;

    my $site = $self->{NOP_site}  = $args->{site};
    foreach my $c (qw/access_token protected_resource authorize refresh_token/)
    {   my $link = $args->{$c.'_url'} || $args->{$c.'_path'} || "/oauth/$c";
        $self->{"NOP_${c}_url"}    = $self->site_url($link);
        $self->{"NOP_${c}_method"} = $args->{$c.'_method'} || 'POST';
        $self->{"NOP_${c}_param"}  = $args->{$c.'_param'}  || [];
    }

    $self;
}

#----------------
=section Accessors
=method id 
=method secret 
=method user_agent 
=method bearer_token_scheme 
=method site 
=method scope 
=method state 
=method hd 
=method grant_type 
=cut

sub id()         {shift->{NOP_id}}
sub id_enc()     {shift->{NOP_id_enc}}
sub secret()     {shift->{NOP_secret}}
sub secret_enc() {shift->{NOP_secret_enc}}
sub user_agent() {shift->{NOP_agent}}
sub site()       {shift->{NOP_site}}
sub scope()      {shift->{NOP_scope}}
sub state()      {shift->{NOP_state}}
sub hd()         {shift->{NOP_hd}}
sub grant_type() {shift->{NOP_grant_type}}

sub bearer_token_scheme() {shift->{NOP_scheme}}

#----------------
=section Actions

=subsection HTTP

=method request $request, [$more]
Send the $request (a M<HTTP::Request> object) to the server, calling
M<LWP::UserAgent> method C<request()>.  This method will NOT add
security token information to the message.
=cut

sub request($@)
{   my ($self, $request) = (shift, shift);
#print $request->as_string;
    my $response = $self->user_agent->request($request, @_);
#print $response->as_string;
#$response;
}

=method request_auth $token, <$request | <$method, $uri, [$header, $content]>>
Send an authorized request: the $token information gets included in the
request object.  Returns the answer (M<HTTP::Response>).

=examples
  my $auth  = Net::OAuth2::Profile::WebServer->new(...);
  my $token = $auth->get_access_token($code, ...);

  # possible...
  my $resp  = $auth->request_auth($token, GET => $uri, $header, $content);
  my $resp  = $auth->request_auth($token, $request);

  # nicer (?)
  my $resp  = $token->get($uri, $header, $content);
  my $resp  = $token->request($request);
=cut

sub request_auth(@)
{   my ($self, $token) = (shift, shift);
    my $request;
    if(@_==1) { $request = shift }
    else
    {   my ($method, $uri, $header, $content) = @_;
        $request = HTTP::Request->new
          ( $method => $self->site_url($uri)
          , $header, $content
          );
    }
    $self->add_token($request, $token, $self->bearer_token_scheme);
    $self->request($request);
}

#--------------------
=section Helpers

=method site_url <$uri|$path>, $params
Construct a URL to address the site.  When a full $uri is passed, it appends
the $params as query parameters.  When a $path is provided, it is relative
to M<new(site)>.
=cut

sub site_url($@)
{   my ($self, $path) = (shift, shift);
    my @params = @_==1 && ref $_[0] eq 'HASH' ? %{$_[0]} : @_;
    my $site = $self->site;
    my $uri  = $site ? URI->new_abs($path, $site) : URI->new($path);
    $uri->query_form($uri->query_form, @params) if @params;
    $uri;
}

=method add_token $request, $token, $scheme
Merge information from the $token into the $request following the the
bearer token $scheme.  Supported schemes:

=over 4
=item * auth-header or auth-header:REALM
Adds an C<Authorization> header to requests.  The default REALM is C<OAuth>,
but C<Bearer> and C<OAuth2> may work as well.

=item * uri-query or uri-query:FIELD
Adds the token to the query parameter list.
The default FIELD name used is C<oauth_token>.

=item * form-body or form-body:FIELD
Adds the token to the www-form-urlencoded body of the request.
The default FIELD name used is C<oauth_token>.
=back
=cut

sub add_token($$$)
{   my ($self, $request, $token, $bearer) = @_;
    my $access  = $token->access_token;

    my ($scheme, $opt) = split ':', $bearer;
    $scheme = lc $scheme;
    if($scheme eq 'auth-header')
    {   # Specs suggest using Bearer or OAuth2 for this value, but OAuth
        # appears to be the de facto accepted value.
        # Going to use OAuth until there is wide acceptance of something else.
        my $auth_scheme = $opt || 'OAuth';
        $request->headers->header(Authorization => "$auth_scheme $access");
    }
    elsif($scheme eq 'uri-query')
    {   my $query_param = $opt || 'oauth_token';
        $request->uri->query_form($request->uri->query_form
          , $query_param => $access);
    }
    elsif($scheme eq 'form-body')
    {   $request->headers->content_type eq MIME_URLENC
            or die "embedding access token in request body is only valid "
                 . "for 'MIME_URLENC' content type";

        my $query_param = $opt || 'oauth_token';
        my $content     = $request->content;
        $request->add_content(($content && length $content ?  '&' : '')
           . uri_escape($query_param).'='.uri_escape($access));
    }
    else
    {   carp "unknown bearer schema $bearer";
    }

    $request;
}

=method build_request $method, $uri, $params
Returns a M<HTTP::Request> object.  $params is an HASH or an ARRAY-of-PAIRS
of query parameters.
=cut

sub build_request($$$)
{   my ($self, $method, $uri_base, $params) = @_;
    my %params = ref $params eq 'HASH' ? %$params : @$params;

    # rfc6749 section "2.3.1. Client Password"
    # The Auth Header is always supported, but client_id/client_secret as
    # parameters may be as well.  We do both when ->new(secrets_in_params)
    # to support old servers.
    delete @params{qw/client_id client_secret/}
        unless $self->{NOP_show_secret};

    my $request;

    if($method eq 'POST')
    {   my $p = URI->new('http:');   # taken from HTTP::Request::Common
        $p->query_form(%params);

        $request = HTTP::Request->new
          ( $method => $uri_base
          , [Content_Type => MIME_URLENC]
          , $p->query
          );
    }
    elsif($method eq 'GET')
    {   my $uri = blessed $uri_base && $uri_base->isa('URI')
          ? $uri_base->clone : URI->new($uri_base);

        $uri->query_form($uri->query_form, %params);
        $request = HTTP::Request->new($method, $uri);
    }
    else
    {   confess "unknown request method $method";
    }

    my $uri  = $request->uri;
    my $head = $request->headers;
    $request->protocol('HTTP/1.1');

    # 2016-01-15 Instagram does not like the portnumber to appear
    # my ($host, $port) = ($uri->host, $uri->port);
    # $host .= ':'.$port if $port != $uri->default_port;
    $head->header(Host => $uri->host);

    $head->header(Connection => 'Keep-Alive');
    $request;
}

=method params_from_response $response, $reason
Decode information from the $response by the server (an M<HTTP::Response>
object). The $reason for this answer is used in error messages.
=cut

sub params_from_response($$)
{   my ($self, $response, $why) = @_;
    my ($error, $content);
    $content = $response->decoded_content || $response->content if $response;

    if(!$response)
    {   $error = 'no response received';
    }
    elsif(!$response->is_success)
    {   $error = 'received error: '.$response->status_line;
    }
    else
    {   # application/json is often not correctly configured: is not
        # (yet) an apache pre-configured extension   :(
        if(my $params = eval {decode_json $content} )
        {   # content is JSON
            return ref $params eq 'HASH' ? %$params : @$params;
        }

        # otherwise form-encoded parameters (I hope)
        my $uri     = URI->new;
        $uri->query($content);
        my @res_params = $uri->query_form;
        return @res_params if @res_params;

        $error = "cannot read parameters from response";
    }
    
    substr($content, 200) = '...' if length $content > 200;
    die "failed oauth call $why: $error\n$content\n";
}

sub authorize_method()          {panic}  # user must use autorize url
sub access_token_method()       {shift->{NOP_access_token_method} }
sub refresh_token_method()      {shift->{NOP_refresh_token_method} }
sub protected_resource_method() {shift->{NOP_protected_resource_method} }

sub authorize_url()             {shift->{NOP_authorize_url}}
sub access_token_url()          {shift->{NOP_access_token_url}}
sub refresh_token_url()         {shift->{NOP_refresh_token_url}}
sub protected_resource_url()    {shift->{NOP_protected_resource_url}}

sub authorize_params(%)
{   my $self   = shift;
    my %params = (@{$self->{NOP_authorize_param}}, @_);
    $params{scope}         ||= $self->scope;
    $params{state}         ||= $self->state;
    $params{hd}            ||= $self->hd;
    $params{client_id}     ||= $self->id;
    \%params;
}

sub access_token_params(%)
{   my $self   = shift;
    my %params = (@{$self->{NOP_access_token_param}}, @_);
    $params{code}          ||= '';
    $params{client_id}     ||= $self->id;
    $params{client_secret} ||= $self->secret;
    $params{grant_type}    ||= $self->grant_type;
    \%params;
}

sub refresh_token_params(%)
{   my $self   = shift;
    my %params = (@{$self->{NOP_refresh_token_param}}, @_);
    $params{client_id}     ||= $self->id;
    $params{client_secret} ||= $self->secret;
    \%params;
}

sub protected_resource_params(%)
{   my $self   = shift;
    my %params = (@{$self->{NOP_protected_resource_param}}, @_);
    \%params;
}

1;
