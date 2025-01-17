###############################################################################
# OpenVAS Vulnerability Test
#
# Odoo Management Software Remote Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812511");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-02-08 11:46:24 +0530 (Thu, 08 Feb 2018)");
  script_name("Odoo Management Software Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Odoo management software.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

foreach dir(make_list_unique("/", "/Odoo", "/odoo_cms", "/odoo_cmr", "/CMR", http_cgi_dirs(port:port))) {

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache(item:dir + "/web/login", port:port);

  if("Log in with Odoo.com" >< res && (res =~ '(P|p)owered by.*>Odoo' || 'content="Odoo' >< res) &&
     ">Log in" >< res) {

    version = "unknown";
    set_kb_item(name:"Odoo/Detected", value:TRUE);

    cpe = "cpe:/a:odoo:odoo";

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data:build_detection_report(app:"Odoo",
                                            version:version,
                                            install:install,
                                            cpe:cpe),
                                            port:port);
    exit(0);
  }
}
exit(0);
