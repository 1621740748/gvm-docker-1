###############################################################################
# OpenVAS Vulnerability Test
#
# HP LaserJet Printers Unauthenticated Access
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103390");
  script_cve_id("CVE-1999-1061");
  script_version("2020-08-24T08:40:10+0000");
  script_name("HP LaserJet Printers Unauthenticated Access");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2012-01-13 10:43:06 +0100 (Fri, 13 Jan 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports(23);
  script_mandatory_keys("telnet/hp/jetdirect/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Connect to this printer via telnet and set a password by executing
  the 'passwd' command.");

  script_tag(name:"summary", value:"HP Laserjet printers with JetDirect cards, when configured with
  TCP/IP, can be configured without a password, which allows remote attackers to connect to the printer
  and change its IP address or disable logging.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );
if( ! banner || "HP JetDirect" >!< banner )
  exit( 0 );

if( "Enter username:" >< banner )
  exit( 99 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

telnet_negotiate( socket:soc ); #nb: Just receive the initial banner
send( socket:soc, data:'/\r\n' );
buf = recv( socket:soc, length:1024 );
send( socket:soc, data:'exit\r\n' );
close( soc );

if( "JetDirect Telnet Configuration" >< buf || "Password is not set" >< banner ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
