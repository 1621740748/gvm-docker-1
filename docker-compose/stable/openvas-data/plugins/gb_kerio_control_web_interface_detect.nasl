###############################################################################
# OpenVAS Vulnerability Test
#
# Kerio Control Web Interface Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140067");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-11-17 12:32:06 +0100 (Thu, 17 Nov 2016)");
  script_name("Kerio Control Web Interface Detection");

  script_tag(name:"summary", value:"The script performs HTTP based detection of the Kerio Control Web Interface");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 4081);
  script_mandatory_keys("KCEWS/banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

include("host_details.inc");

port = http_get_port( default:4081 );

banner = http_get_remote_headers( port:port );

if( "Server: Kerio Control Embedded Web Server" >!< banner ) exit( 0 );

set_kb_item( name:"kerio/control/webiface", value:TRUE );

cpe = 'cpe:/a:kerio:control';

register_product( cpe:cpe, location:"/", port:port, service:"www" );

log_message( port:port, data:'The Kerio Connect Web Interface is running at this port\nCPE: ' + cpe + '\n');

exit( 0 );
