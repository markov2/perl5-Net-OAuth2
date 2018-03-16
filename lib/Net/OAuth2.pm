# This code is part of distribution Net-OAuth2.  Meta-POD processed
# with OODoc into POD and HTML manual-pages.  See README.md
# Copyright Mark Overmeer.  Licensed under the same terms as Perl itself.

package Net::OAuth2;

use warnings;
use strict;

=chapter NAME

Net::OAuth2 - OAuth 2.0 implementation

=chapter SYNOPSIS
  See Net::OAuth2::Profile::WebServer->new

=chapter DESCRIPTION
OAuth version 2.0 is a follow-up on OAuth 1.0, which is not supported by
this module.  The specification for version 2.0 can be found in

=over 4
=item . RFC6749, Authorization framework: L<http://tools.ietf.org/html/rfc6749>
=item . RFC6750, Bearer token usage: L<http://tools.ietf.org/html/rfc6750>
=back

Start with one these modules:

=over 4
=item . M<Net::OAuth2::Profile::WebServer>
=item . M<Net::OAuth2::Profile::Password>
=back

=cut

1;
