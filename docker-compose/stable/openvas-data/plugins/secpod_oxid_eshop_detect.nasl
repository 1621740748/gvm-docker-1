###############################################################################
# OpenVAS Vulnerability Test
#
# OXID eShop Community Edition Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900932");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("OXID eShop Community Edition Version Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of OXID eShop.");

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

foreach dir( make_list_unique( "/", "/oxid", "/eshop", "/oxid-eshop", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item: dir + "/admin/", port:port );

  if( "OXID eShop Login" >< res && res =~ "OXID eShop (Enterprise|Professional|Community)" ) {
    version = "unknown";

    # Just major version e.g. OXID eShop Enterprise Edition, Version 6
    ver = eregmatch(pattern:"Version ([0-9.]+)", string:res);
    if( !isnull(ver[1]) ) version = ver[1];

    ed = eregmatch(pattern: "OXID eShop (Enterprise|Professional|Community)", string: res);
    if (!isnull(ed[1])) {
      edition = ed[1];
      set_kb_item(name: "oxid_eshop/edition", value: edition);
    }

    set_kb_item(name: "oxid_eshop/installed", value: TRUE);

    cpe = build_cpe( value: version, exp:"^([0-9.]+)", base:"cpe:/a:oxid:eshop:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:oxid:eshop';

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"OXID eShop " + edition + " Edition", version:version,
                                              install:install, cpe:cpe, concluded:ver[0] ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
