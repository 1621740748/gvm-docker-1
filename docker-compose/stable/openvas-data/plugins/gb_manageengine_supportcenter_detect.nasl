###############################################################################
# OpenVAS Vulnerability Test
#
# ManageEngine SupportCenter Plus Remote Detection
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805806");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-06-25 12:03:58 +0530 (Thu, 25 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ManageEngine SupportCenter Plus Remote Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  ManageEngine SupportCenter.

  This script sends an HTTP GET request and tries to confirm the application from
  the response, get the version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

http_port = http_get_port(default:8080);

res = http_get_cache(item:"/", port:http_port);

if(">ManageEngine SupportCenter Plus<" >< res &&
                           "ZOHO Corp" >< res)
{
  appVer = eregmatch(pattern:"style.css\?([0-9.]+)", string:res);
  if(!appVer[1]){
    appVer = eregmatch(pattern:"default-theme.css\?([0-9.]+)", string:res);
  }
  if(!appVer[1]){
    appVer = eregmatch(pattern:'BUILD_NO":"([0-9.]+)', string:res);
  }

  if(appVer[1]){
    appVer = appVer[1];
  } else {
    appVer = "Unknown";
  }

  set_kb_item(name:"ManageEngine/SupportCenter/Plus/installed",value:TRUE);

  cpe = build_cpe(value:appVer, exp:"^([0-9.]+)", base:"cpe:/a:manageengine:supportcenter_plus:");
  if(isnull(cpe))
    cpe = "cpe:/a:manageengine:supportcenter_plus";

  register_product(cpe:cpe, location:"/", port:http_port, service:"www");
  log_message(data: build_detection_report(app:"ManageEngine SupportCenter Plus",
                                           version:appVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:appVer),
                                           port:http_port);
}
