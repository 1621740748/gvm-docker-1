###############################################################################
# OpenVAS Vulnerability Test
#
# Sony Network Camera Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.114022");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-08-21 15:13:40 +0200 (Tue, 21 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sony Network Camera Detection");

  script_tag(name:"summary", value:"Detection of Sony Network Camera.

  The script sends a connection request to the server and attempts to detect Sony Network Camera.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://pro.sony/en_EE/products/ip-cameras");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/command/inquiry.cgi?inqjs=sysinfo");

if("ModelName=" >< res || "SoftVersion=" >< res || "TitleBar=" >< res || "Time=" >< res || "TimeZone=" >< res || "DateFormat=" >< res) {
   version = "unknown";
   model = "unknown";
   install = "/";

   #SoftVersion="1.30"
   ver = eregmatch(pattern: '[Ss]oft[Vv]ersion="([0-9.]+)"', string: res);
   if(ver[1]) version = ver[1];

   #ModelName="SNC-RZ25N"
   mod = eregmatch(pattern: '([Mm]odel[Nn]ame="SNC-([0-9a-zA-Z]+)")|Basic realm="Sony Network Camera SNC-([0-9a-zA-z]+)"', string: res);
   if(mod[2]) model = mod[2];
   else if(mod[3]) model = mod[3];

   conclUrl = http_report_vuln_url(port: port, url: "/command/inquiry.cgi?inqjs=sysinfo", url_only: TRUE);

   set_kb_item(name: "sony/network_camera/detected", value: TRUE);
   set_kb_item(name: "sony/network_camera/" + port + "/detected", value: TRUE);
   set_kb_item(name: "sony/network_camera/version", value: version);
   set_kb_item(name: "sony/network_camera/model", value: model);

   register_and_report_cpe(app: "Sony Network Camera", ver: version, base: "cpe:/h:sony:network_camera:", expr: "^([0-9.]+)", insloc: install, regPort: port, conclUrl: conclUrl, extra: "Model: " + model);
}

exit(0);
