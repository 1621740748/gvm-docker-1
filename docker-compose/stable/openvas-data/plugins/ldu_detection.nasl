###############################################################################
# OpenVAS Vulnerability Test
#
# Detects LDU version
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2006 Josh Zlatin-Amishav
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
  script_oid("1.3.6.1.4.1.25623.1.0.19602");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-05-14T13:11:51+0000");
  script_tag(name:"last_modification", value:"2021-05-14 13:11:51 +0000 (Fri, 14 May 2021)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Land Down Under (LDU) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2006 Josh Zlatin-Amishav");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.neocrome.net/");

  script_tag(name:"summary", value:"HTTP based detection of Land Down Under (LDU).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/" , http_cgi_dirs(port:port) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/index.php", port:port);

  # If it looks like LDU.
  if( # Cookie from LDU
      "^Set-Cookie: LDUC" >< res ||
      # Meta tag (generator) from LDU
      'content="Land Down Under Copyright Neocrome' >< res ||
      # Meta tag (keywords) from LDU
      'content="LDU,land,down,under' >< res ) {

    version = "unknown";

    # First we'll try to grab the version from the main page
    pat = "Powered by <a [^<]+ LDU ([0-9.]+)<";
    matches = egrep( pattern:pat, string:res );
    if( matches ) {
      foreach match( split( matches ) ) {
        match = chomp( match );
        ver = eregmatch( pattern:pat, string:match );
        if( ! isnull( ver ) ) {
          version = ver[1];
          break;
        }
      }
    }

    #If unsuccessful try grabbing the version from the readme.old_documentation.htm file.
    if( version == "unknown" ) {
      req = http_get( item:dir + "/docs/readme.old_documentation.htm", port:port );
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

      pat = 'id="top"></a>Land Down Under v([0-9]+)<';
      matches = egrep( pattern:pat, string:res );
      if( matches ) {
        foreach match( split( matches ) ) {
          match = chomp( match );
          ver = eregmatch( pattern:pat, string:match );
          if( ! isnull( ver ) ) {
            version = ver[1];
            break;
          }
        }
      }
    }

    set_kb_item( name:"ldu/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:neocrome:land_down_under:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:neocrome:land_down_under';

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data: build_detection_report( app:"Land Down Under (LDU)",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded:ver[0] ),
                                               port:port );
  }
}

exit( 0 );
