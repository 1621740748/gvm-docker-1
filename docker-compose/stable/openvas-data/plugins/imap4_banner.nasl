# OpenVAS Vulnerability Test
# Description: IMAP Server type and version
#
# Authors:
# Vincent Renardias <vincent@strongholdnet.com>
#
# Copyright:
# Copyright (C) 2005 StrongHoldNet
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11414");
  script_version("2020-11-10T15:30:28+0000");
  script_tag(name:"last_modification", value:"2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IMAP Server type and version");
  script_copyright("Copyright (C) 2005 StrongHoldNet");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/imap", 143, 993);

  script_tag(name:"summary", value:"This detects the IMAP Server's type and version by connecting to
  the server and processing the received banner.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("list_array_func.inc");
include("imap_func.inc");
include("port_service_func.inc");

ports = imap_get_ports();
foreach port( ports ) {

  # nb: imap_get_banner() is verifying (via imap_verify_banner) that we have
  # received an IMAP banner here so it is safe to register the service below.
  banner = imap_get_banner( port:port );
  if( ! banner )
    continue;

  if( service_is_unknown( port:port ) )
    service_register( port:port, proto:"imap", message:"An IMAP Server seems to be running on this port." );

  guess = NULL;
  capas = NULL;

  if( get_port_transport( port ) > ENCAPS_IP )
    is_tls = TRUE;
  else
    is_tls = FALSE;

  set_kb_item( name:"imap/banner/available", value:TRUE );
  set_kb_item( name:"pop3_imap_or_smtp/banner/available", value:TRUE );

  id_banner = get_kb_item( "imap/fingerprints/" + port + "/id_banner" );

  # Dovecot ready.
  # Dovecot (Debian) ready.
  # * ID ("name" "Dovecot")
  if( ( "Dovecot " >< banner && " ready" >< banner ) || "Dovecot" >< id_banner ) {
    set_kb_item( name:"imap/dovecot/detected", value:TRUE );
    set_kb_item( name:"imap_or_pop3/dovecot/detected", value:TRUE );
    set_kb_item( name:"imap/" + port + "/dovecot/detected", value:TRUE );
    guess += '\n- Dovecot';
  }

  if( "WorldMail IMAP4 Server" >< banner ) {
    set_kb_item( name:"imap/eudora/worldmail/detected", value:TRUE );
    set_kb_item( name:"imap/" + port + "/eudora/worldmail/detected", value:TRUE );
    guess += '\n- Eudora WorldMail IMAP Server';
  }

  if( banner =~ "MERCUR.*IMAP4.Server" ) {
    set_kb_item( name:"imap/mercur/detected", value:TRUE );
    set_kb_item( name:"imap/" + port + "/mercur/detected", value:TRUE );
    guess += '\n- Mercur Mailserver/Messaging';
  }

  if( "Softalk Mail Server" >< banner ) {
    set_kb_item( name:"imap/softalk/detected", value:TRUE );
    set_kb_item( name:"imap/" + port + "/softalk/detected", value:TRUE );
    guess += '\n- Softalk Mail Server';
  }

  if( "Code-Crafters" >< banner && "Ability Mail Server" >< banner ) {
    set_kb_item( name:"imap/codecrafters/ability/detected", value:TRUE );
    set_kb_item( name:"imap/" + port + "/codecrafters/ability/detected", value:TRUE );
    guess += '\n- Code-Crafters Ability Mail Server';
  }

  if( "CommuniGate Pro IMAP Server" >< banner ) {
    set_kb_item( name:"imap/communigate/pro/detected", value:TRUE );
    set_kb_item( name:"imap/" + port + "/communigate/pro/detected", value:TRUE );
    guess += '\n- Code-Crafters Ability Mail Server';
  }

  if( " MDaemon " >< banner ) {
    set_kb_item( name:"imap/mdaemon/detected", value:TRUE );
    set_kb_item( name:"imap/" + port + "/mdaemon/detected", value:TRUE );
    guess += '\n- MDaemon IMAP Server';
  }

  if( "Cyrus IMAP" >< banner && "server ready" >< banner ) {
    set_kb_item( name:"imap/cyrus/detected", value:TRUE );
    set_kb_item( name:"imap/" + port + "/cyrus/detected", value:TRUE );
    guess += '\n- Cyrus IMAP Server';
  }

  if( banner =~ "FirstClass IMAP" ) {
    set_kb_item( name:"imap/opentext/firstclass/detected", value:TRUE );
    set_kb_item( name:"imap/" + port + "/opentext/firstclass/detected", value:TRUE );
    guess += '\n- OpenText FirstClass';
  }

  if( banner =~ "Xpressions IMAP" ) {
    set_kb_item( name:"imap/unify/xpressions/detected", value:TRUE );
    set_kb_item( name:"imap/" + port + "/unify/xpressions/detected", value:TRUE );
    guess += '\n- Unify OpenScape Xpressions';
  }

  if( banner =~ "Domino IMAP4 Server" ) {
    set_kb_item( name:"imap/hcl/domino/detected", value:TRUE );
    set_kb_item( name:"imap/" + port + "/hcl/domino/detected", value:TRUE );
    guess += '\n- HCL Domino';
  }

  if( banner =~ "IceWarp" ) {
    set_kb_item( name:"imap/icewarp/mailserver/detected", value:TRUE );
    set_kb_item( name:"imap/" + port + "/icewarp/mailserver/detected", value:TRUE );
    guess += '\n- IceWarp Mail Server';
  }

  report = 'Remote IMAP server banner:\n\n' + banner;
  if( strlen( guess ) > 0 )
    report += '\n\nThis is probably:\n' + guess;

  if( is_tls )
    capalist = get_kb_list( "imap/fingerprints/" + port + "/tls_capalist" );
  else
    capalist = get_kb_list( "imap/fingerprints/" + port + "/nontls_capalist" );

  if( capalist && is_array( capalist ) ) {
    # Sort to not report changes on delta reports if just the order is different
    capalist = sort( capalist );
    foreach capa( capalist ) {
      if( ! capas )
        capas = capa;
      else
        capas += ", " + capa;
    }
  }

  if( strlen( capas ) > 0 ) {
    capa_report = '\n\nThe remote IMAP server is announcing the following available CAPABILITIES via an ';
    if( is_tls )
      capa_report += "encrypted";
    else
      capa_report += "unencrypted";
    report += capa_report += ' connection:\n\n' + capas;
  }

  log_message( port:port, data:report );
}

exit( 0 );
