##############################################################################
# OpenVAS Vulnerability Test
#
# XOOPS Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900892");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)");
  script_name("XOOPS Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed XOOPS version.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

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

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/xoops", http_cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item: dir + "/index.php", port:port );
  res2 = http_get_cache( item: dir + "/user.php", port:port );

  if( ( res =~ "^HTTP/1\.[01] 200" && ( 'generator" content="XOOPS" />' >< res || ">Powered by XOOPS" >< res || ">The XOOPS Project<" >< res || ( "/xoops.css" >< res && "/xoops.js" >< res ) ) ) ||
      ( res2 =~ "^HTTP/1\.[01] 200" && ( 'generator" content="XOOPS" />' >< res || ">Powered by XOOPS" >< res || ">The XOOPS Project<" >< res || ( "/xoops.css" >< res && "/xoops.js" >< res ) ) ) ) {

    version = "unknown";
    conclUrl = NULL;
    if( install == "/" ) rootInstalled = TRUE;

    # This will only work if XOOPS is incorrectly deployed (e.g. whole install archive is extracted into document root, not only the content of the /htdocs folder)
    url = dir + "/../release_notes.txt";
    req = http_get( item:url , port:port );
    res = http_keepalive_send_recv( port:port, data:req );

    if( res =~ "^HTTP/1\.[01] 200" && "XOOPS" >< res && "version" >< res ) {

      ver = eregmatch( pattern:"XOOPS ([0-9]\.[0-9.]+).?(Final|RC[0-9]|[a-z])?", string:res, icase:TRUE );
      if( ! isnull( ver[1] ) ) {
        if( ! isnull( ver[2] ) ) {
          version = ver[1] + "." + ver[2];
        } else {
          version = ver[1];
        }
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    if( version == "unknown" ) {
      # For newer versions (e.g. 2.5.8)
      url = dir + "/class/libraries/composer.json";
      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv( port:port, data:req );

      ver = eregmatch( pattern:"Libraries for XOOPS ([0-9]\.[0-9.]+).?(Final|RC[0-9]|[a-z])?", string:res, icase:TRUE );
      if( ! isnull( ver[1] ) ) {
        if( ! isnull( ver[2] ) ) {
          version = ver[1] + "." + ver[2];
        } else {
          version = ver[1];
        }
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/XOOPS", value:tmp_version );
    set_kb_item( name:"XOOPS/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:xoops:xoops:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:xoops:xoops";

    register_product( cpe:cpe, location:install, port:port, service:"www" );
    log_message( data:build_detection_report( app:"XOOPS",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
