package Net::OAuth2;

use warnings;
use strict;

=chapter NAME

Net::OAuth2 - OAuth 2.0 implementation

=chapter SYNOPSIS
  # See demo directory in the distribution for practicle examples.

  my $client = Net::OAuth2::Profile::WebServer->new
    ( client_id     => $client_id
    , client_secret => $client_secret
    , site          => 'https://graph.facebook.com'
    , redirect_uri  => uri_for('/auth/facebook/callback')
    );

  my $url          = $client->authorize_url;

  my $access_token = $client->get_access_token(params->{code});
  my $response = $access_token->get('/me');
  $response->is_success
      or die "error: " . $response->status_line;

  print "Yay, it worked: " . $response->decoded_content;

=chapter DESCRIPTION
OAuth version 2.0 follows OAuth 1.0, which is not supported by this
module.  The specification can be found in

=over 4
=item RFC6749, Authorization framework: L<http://tools.ietf.org/html/rfc6749>
=item RFC6750, Bearer token usage: L<http://tools.ietf.org/html/rfc6750>
=back

=cut

1;
