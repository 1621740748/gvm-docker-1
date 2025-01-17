###############################################################################
# OpenVAS Vulnerability Test
#
# Service Detection with '<xml/>' Request
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108198");
  script_version("2021-06-18T12:11:02+0000");
  script_tag(name:"last_modification", value:"2021-06-18 12:11:02 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"creation_date", value:"2017-07-20 14:08:04 +0200 (Thu, 20 Jul 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection with '<xml/>' Request");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service1.nasl", "find_service2.nasl", "find_service_3digits.nasl");
  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin performs service detection.

  This plugin is a complement of find_service.nasl. It sends a '<xml/>'
  request to the remaining unknown services and tries to identify them.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("global_settings.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = get_kb_item( "Services/unknown" );
if( ! port ) exit( 0 );
if( ! get_port_state( port ) ) exit( 0 );
if( ! service_is_unknown( port:port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

vt_strings = get_vt_strings();

req = "<" + vt_strings["lowercase"] + "/>";
send( socket:soc, data:req + '\r\n' );
r = recv( socket:soc, length:4096 );
close( soc );

if( ! r ) {
  debug_print( 'service on port ', port, ' does not answer to "' + req + '\\r\\n"' );
  exit( 0 );
}

k = "FindService/tcp/" + port + "/xml";
set_kb_item( name:k, value:r );

rhexstr = hexstr( r );
if( '\0' >< r )
  set_kb_item( name:k + "Hex", value:rhexstr );

# nb: Zabbix Server is answering with an "OK" here but find_service4.nasl will take the job

if( "oap_response" >< r && "GET_VERSION" >< r ) {
  service_register( port:port, proto:"oap", message:"A OpenVAS Administrator service supporting the OAP protocol seems to be running on this port." );
  log_message( port:port, data:"A OpenVAS Administrator service supporting the OAP protocol seems to be running on this port." );
  exit( 0 );
}

# nb: The GMP service of early GVM-10 versions still answered with an omp_response
# so we only differ between the protocol based on its version detected by
# gb_openvas_manager_detect.nasl.
#
# Examples:
# GOS 3.1 / OpenVAS-8 and probably prior:  <omp_response status="400" status_text="First command must be AUTHENTICATE, COMMANDS or GET_VERSION"/>
# GOS 4.x+ / OpenVAS-9 / GVM-10 and later: <gmp_response status="400" status_text="Only command GET_VERSION is allowed before AUTHENTICATE"/>
if( "GET_VERSION" >< r && ( "omp_response" >< r || "gmp_response" >< r ) ) {
  service_register( port:port, proto:"omp_gmp", message:"A OpenVAS / Greenbone Vulnerability Manager supporting the OMP/GMP protocol seems to be running on this port." );
  log_message( port:port, data:"A OpenVAS / Greenbone Vulnerability Manager supporting the OMP/GMP protocol seems to be running on this port." );
  exit( 0 );
}

# nb: Check_MK Agent, find_service1.nasl should already do the job but sometimes the Agent behaves strange
# and only sends data too late. This is a fallback for such a case.
if( "<<<check_mk>>>" >< r || "<<<uptime>>>" >< r || "<<<services>>>" >< r || "<<<mem>>>" >< r ) {
  # nb: Check_MK Agents seems to not answer to repeated requests in a short amount of time so saving the response here for later processing.
  replace_kb_item( name:"check_mk_agent/banner/" + port, value:r );
  service_register( port:port, proto:"check_mk_agent", message:"A Check_MK Agent seems to be running on this port." );
  log_message( port:port, data:"A Check_MK Agent seems to be running on this port." );
  exit( 0 );
}

# 0x00:  4A 44 57 50 2D 48 61 6E 64 73 68 61 6B 65          JDWP-Handshake
# nb: Covered in various find_service*.nasl because the service seems to be unstable and
# we want to try our best to detect this service.
if( r == "JDWP-Handshake" ) {
  service_register( port:port, proto:"jdwp", message:"A Java Debug Wired Protocol (JDWP) service is running at this port." );
  log_message( port:port, data:"A Java Debug Wired Protocol (JDWP) service is running at this port." );
  exit( 0 );
}

# Port 264/tcp
#
# 0x00:  59 00 00 00                                        Y...
#
# or:
#
# 0x00:  51 00 00 00                                        Q...
#
# nb: See find_service1.nasl and find_service2.nasl as well
if( rhexstr =~ "^5[19]000000$" ) {
  service_register( port:port, proto:"fw1-topology", message:"A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
  log_message( port:port, data:"A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
  exit( 0 );
}

########################################################################
#             Unidentified service                                     #
########################################################################

if( ! r0 ) unknown_banner_set( port:port, banner:r );
