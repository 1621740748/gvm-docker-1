###############################################################################
# OpenVAS Vulnerability Test
#
# Kamailio Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105591");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-04-14T08:50:25+0000");
  script_tag(name:"last_modification", value:"2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)");
  script_tag(name:"creation_date", value:"2016-03-31 14:38:23 +0200 (Thu, 31 Mar 2016)");
  script_name("Kamailio Detection (SIP)");

  script_tag(name:"summary", value:"This scripts try to detect a Kamailio SIP server from the SIP banner.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/banner/available");

  exit(0);
}

include("host_details.inc");
include("sip.inc");
include("misc_func.inc");
include("port_service_func.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos["port"];
proto = infos["proto"];

if( ! banner = sip_get_banner( port:port, proto:proto ) )
  exit( 0 );

if( "kamailio" >!< banner )
  exit( 0 );

vers = "unknown";
cpe = "cpe:/a:kamailio:kamailio";

set_kb_item( name:"kamailio/installed", value:TRUE );

version = eregmatch( pattern:'kamailio \\(([^ )]+) ', string:banner );
if( ! isnull( version[1] ) ) {
  vers = version[1];
  cpe += ":" + vers;
  set_kb_item( name:"kamailio/version", value:vers );
}

location = port + "/" + proto;

register_product( cpe:cpe, port:port, location:location, service:"sip", proto:proto );

log_message( data: build_detection_report( app:"kamailio", version:vers, install:location, cpe:cpe, concluded:banner ), port:port, proto:proto );
exit( 0 );
