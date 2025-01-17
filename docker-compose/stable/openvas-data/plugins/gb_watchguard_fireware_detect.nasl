###############################################################################
# OpenVAS Vulnerability Test
#
# Watchguard Fireware XTM Web UI Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.106078");
  script_version("2021-04-15T13:23:31+0000");
  script_tag(name:"last_modification", value:"2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2016-05-20 11:10:26 +0700 (Fri, 20 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Watchguard Fireware XTM Web UI Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.watchguard.com/products/fireware-xtm.asp");

  script_tag(name:"summary", value:"Detection of Watchguard Fireware XTM Web UI

  The script sends a connection request to the server and attempts to detect Watchguard Fireware XTM Web UI");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:8080 );

res = http_get_cache( item: "/", port:port );

if( ">The <b>Fireware XTM Web UI from WatchGuard</b>" >< res ||
    "<title>Fireware XTM User Authentication</title>" >< res ||
    "/wgcgi.cgi?action=fw_logon" >< res ) {

  vers = "unknown";
  install = "/";

  set_kb_item( name:"www/" + port + "/watchguard_fireware", value:vers );
  set_kb_item( name:"watchguard_fireware/installed", value: TRUE );

  cpe = 'cpe:/o:watchguard:fireware';

  register_product( cpe:cpe, location:install, port:port, service:"www" );
  os_register_and_report( os:"WatchGuard Fireware", cpe:cpe, banner_type:"HTTP(s) Login Page", port:port, desc:"Watchguard Fireware XTM Web UI Detection", runs_key:"unixoide" );

  log_message( data:build_detection_report( app:"Watchguard Fireware XTM OS",
                                            version:vers,
                                            install:install,
                                            cpe:cpe ),
                                            port:port );
}

exit( 0 );
