###############################################################################
# OpenVAS Vulnerability Test
#
# Zimbra Collaboration Detection (WebGUI)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103852");
  script_version("2021-04-20T03:37:55+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-20 03:37:55 +0000 (Tue, 20 Apr 2021)");
  script_tag(name:"creation_date", value:"2013-12-11 11:35:08 +0100 (Wed, 11 Dec 2013)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synacor Zimbra Collaboration Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Synacor Zimbra Collaboration (formerly
  known as Zimbra Collaboration Suite / ZCS).");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:443 );

foreach dir( make_list_unique( "/", "/zimbraAdmin", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item: dir + "/", port:port );

  if( buf =~ "^HTTP/1\.[01] 200" && ( ( "www.zimbra.com" >< buf && "zimbraMail" >< buf ) ||
      "Zimbra Collaboration Suite Web Client" >< buf ||
      "<title>Zimbra Administration" >< buf ||
      "<title>Zimbra Web Client Sign In" >< buf ) ) {

    version = "unknown";

    url = dir + "/js/zimbraMail/share/model/ZmSettings.js";
    req = http_get( port:port, item:url );
    res = http_keepalive_send_recv( port:port, data:req );

    #Modified to detect version if link doesn't go via zimbraAdmin directory.
    if(res  !~ "^HTTP/1\.[01] 200")
    {
      url = "/js/zimbraMail/share/model/ZmSettings.js";
      req = http_get( port:port, item:url );
      res = http_keepalive_send_recv( port:port, data:req );
    }

    if( ! isnull ( res ) ) {
      vers = egrep( string:res, pattern:"CLIENT_VERSION" );
      if( !isnull ( vers)  ) {
        # Example: this.registerSetting("CLIENT_VERSION", {type:ZmSetting.T_CONFIG, defaultValue:"8.7.1_GA_1670"});
        vers = eregmatch( string:vers, pattern:'defaultValue:"([0-9.]+)' );
        if( ! isnull( vers[1] ) ) {
          version = vers[1];
          conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }

    set_kb_item( name:"zimbra_web/installed", value:TRUE );

    cpe1 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:synacor:zimbra_collaboration_suite:" );
    cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:zimbra:zimbra_collaboration_suite:" );
    if( ! cpe1 ) {
      cpe1 = "cpe:/a:synacor:zimbra_collaboration_suite";
      cpe2 = "cpe:/a:zimbra:zimbra_collaboration_suite";
    }

    register_product( cpe:cpe1, location:install, port:port, service:"www" );
    register_product( cpe:cpe2, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Synacor Zimbra Collaboration",
                                              version:version,
                                              install:install,
                                              concluded:vers[0],
                                              concludedUrl:conclUrl,
                                              cpe:cpe1 ),
                  port:port );
    exit( 0 );
  }
}

exit( 0 );
