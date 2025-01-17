###############################################################################
# OpenVAS Vulnerability Test
#
# WS_FTP Server Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900608");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-03-12 10:50:11 +0100 (Thu, 12 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("WS_FTP Server Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/ws_ftp/detected");

  script_tag(name:"summary", value:"This script determines the WS_FTP server version on the remote host
  and sets the result in the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );
banner = ftp_get_banner( port:port );
if(! banner || "WS_FTP Server" >!< banner )
  exit( 0 );

install = port + "/tcp";
version = "unknown";
set_kb_item( name:"ipswitch/ws_ftp_server/detected", value:TRUE );

vers = eregmatch( pattern:"WS_FTP Server ([0-9.]+)", string:banner );
if( ! isnull( vers[1] ) )
  version = vers[1];

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ipswitch:ws_ftp_server:");
if( ! cpe )
  cpe = "cpe:/a:ipswitch:ws_ftp_server";

register_product( cpe:cpe, location:install, port:port, service:"ftp" );

log_message( data:build_detection_report( app:"WS_FTP Server",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:vers[0] ),
             port:port );

exit( 0 );
