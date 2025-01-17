###############################################################################
# OpenVAS Vulnerability Test
#
# Dolphin Version Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808217");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-06-06 15:55:57 +0530 (Mon, 06 Jun 2016)");
  script_name("Dolphin Version Detection");

  script_tag(name:"summary", value:"Check for the presence of Dolphin
  Software.

  This script sends an HTTP GET request and tries to ensure the presence of Dolphin
  from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("list_array_func.inc");

include("host_details.inc");


dol_port = http_get_port(default:80);

if(! http_can_host_php(port:dol_port)) exit(0);

foreach dir(make_list_unique("/", "/dolph", "/dolphin", http_cgi_dirs(port:dol_port)))
{

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + '/administration/profiles.php';
  sndReq = http_get(item:url, port:dol_port);
  rcvRes = http_send_recv(port:dol_port, data:sndReq);

  if("Dolphin" >< rcvRes && "boonex" >< rcvRes && "<title>Login</title>" >< rcvRes &&
     'id="admin_username"' >< rcvRes && 'id="admin_password"' >< rcvRes)
  {
    version = "unknown";

    set_kb_item(name:"Dolphin/Installed", value:TRUE);

    cpe = "cpe:/a:boonex:dolphin";

    register_product(cpe:cpe, location:install, port:dol_port, service:"www");

    log_message(data:build_detection_report(app:"Dolphin",
                                            version:version,
                                            install:install,
                                            cpe:cpe),
                                            port:dol_port);
  }
}
exit(0);
