###############################################################################
# OpenVAS Vulnerability Test
#
# Compaq WBEM Server Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2005 SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10746");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Compaq WBEM Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 2301);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Disable the Anonymous access to Compaq WBEM web server, or
  block the web server's port number on your Firewall.");

  script_tag(name:"summary", value:"We detected the remote web server to be a Compaq WBEM server.
  This web server enables attackers to gather sensitive information on
  the remote host, especially if anonymous access has been enabled.");

  script_tag(name:"insight", value:"Sensitive information includes: Platform name and version (including
  service packs), installed hotfixes, Running services, installed Drivers,
  boot.ini content, registry settings, NetBIOS name, system root directory,
  administrator full name, CPU type, CPU speed, ROM versions and revisions,
  memory size, sever recovery settings, and more.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

CPE = "cpe:/a:hp:http_server:";

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");

port = http_get_port( default:2301 );

buf = http_get_remote_headers( port:port );
if( ! buf )
  exit( 0 );

if( egrep( pattern:"^Server: CompaqHTTPServer/", string:buf ) ) {

  set_kb_item( name:"compaq/http_server/detected", value:TRUE );
  mod_buf = strstr( buf, "Server: CompaqHTTPServer/" );
  mod_buf = mod_buf - "Server: CompaqHTTPServer/";
  subbuf = strstr( mod_buf, string( "\n" ) );
  mod_buf = mod_buf - subbuf;
  version = mod_buf;

  wbem_version = "false";
  if( "var VersionCheck = " >< buf ) {
    concl = buf;
    mod_buf = strstr( buf, "var VersionCheck = " );
    mod_buf = mod_buf - string( "var VersionCheck = " );
    mod_buf = mod_buf - raw_string( 0x22 );
    subbuf = strstr( mod_buf, raw_string( 0x22 ) );
    mod_buf = mod_buf - subbuf;
    wbem_version = mod_buf;
  }

  buf = "Remote Compaq HTTP server version is: ";
  buf = buf + version;
  if( ! ( wbem_version == "false" ) ) {
    buf = string( buf, "\nCompaq WBEM server version: " );
    buf = buf + wbem_version;
  }
  log_message( data:buf, port:port );

  register_and_report_cpe( app:"Compaq WEBM",
                           ver:wbem_version,
                           concluded:concl,
                           base:CPE,
                           expr:"([0-9.]+)",
                           insloc:port + "/tcp",
                           regPort:port,
                           regService:"www" );
}

exit( 0 );
