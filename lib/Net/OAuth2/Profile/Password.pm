package Net::OAuth2::Profile::Password;
use base 'Net::OAuth2::Profile';

use warnings;
use strict;

use URI;
use Net::OAuth2::AccessToken;
use HTTP::Request;

=chapter NAME
Net::OAuth2::Profile::Password - OAuth2 for web-server use

=chapter SYNOPSIS
  my $auth = Net::OAuth2::Profile::Password->new(...);
  $auth->get_access_token(...);

=chapter DESCRIPTION

=chapter METHODS

=section Constructors

=c_method new %options
=default grant_type 'password'
=cut

sub init($)
{   my ($self, $args) = @_;
    $args->{grant_type} ||= 'password';
    $self->SUPER::init($args);
    $self;
}

#-------------------
=section Accessors
=cut

#--------------------
=section Action
=cut

=method get_access_token %options
=requires username USER
=requires password PASSWORD
=cut

sub get_access_token(@)
{   my $self = shift;

    my $request  = $self->build_request
      ( $self->access_token_method
      , $self->access_token_url
      , $self->access_token_params(@_)
      );

    my $response = $self->request($request);

    Net::OAuth2::AccessToken->new(client => $self
      , $self->params_from_response($response, 'access token'));
}

1;
