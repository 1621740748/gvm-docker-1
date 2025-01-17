###############################################################################
# OpenVAS Vulnerability Test
#
# Pandora FMS Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100926");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-12-01 14:30:53 +0100 (Wed, 01 Dec 2010)");

  script_name("Pandora FMS Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract
  the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://pandorafms.org");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/pandora_console", "/fms", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  buf = http_get_cache( item: dir + "/index.php", port:port );

  if( "<title>Pandora FMS -" >< buf ) {

    version = "unknown";

    # ver_num">v7.0NG.740<
    ver = eregmatch( string:buf, pattern:'ver_num">v[0-9.]+NG\\.([0-9]+)<' );
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
    } else {
      ver = eregmatch( string:buf, pattern:">v([0-9.]+(SP[0-9]+)?( Build [a-zA-Z0-9]+)?)", icase:TRUE );

      if( ! isnull( ver[1] ) )
        version = chomp( ver[1] );
    }

    set_kb_item( name:"pandora_fms/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9A-Za-z. ]+)", base:"cpe:/a:artica:pandora_fms:" );
    if( ! cpe )
      cpe = "cpe:/a:artica:pandora_fms";

    cpe = str_replace( string:cpe, find:" ", replace:"_" );

    register_product( cpe:cpe, location:install, port:port , service:"www" );

    log_message( data:build_detection_report( app:"Pandora FMS", version:version, install:install, cpe:cpe,
                                              concluded:ver[0] ),
                 port:port );
  }
}

exit( 0 );
