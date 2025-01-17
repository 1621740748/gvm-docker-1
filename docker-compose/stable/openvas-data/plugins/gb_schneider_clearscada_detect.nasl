###############################################################################
# OpenVAS Vulnerability Test
#
# Schneider Electric ClearSCADA Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.141106");
  script_version("2021-04-15T13:23:31+0000");
  script_tag(name:"last_modification", value:"2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2018-05-17 15:22:07 +0700 (Thu, 17 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Schneider Electric ClearSCADA Detection");

  script_tag(name:"summary", value:"Detection of Schneider Electric ClearSCADA.

  The script sends a connection request to the server and attempts to detect Schneider Electric ClearSCADA and to
  extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://software.schneider-electric.com/products/clearscada/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/");

if ('title="ClearSCADA Home"' >< res && "CurUser" >< res) {
  version = "unknown";

  # Server: ClearSCADA/6.74.5192.1
  vers = eregmatch(pattern: "Server: ClearSCADA/([0-9.]+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];
  else {
    url = "/alarms/";
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);

    # /file/ViewXCtrl-77.cab#Version=6,77,5882,0"
    vers = eregmatch(pattern: "cab#Version=([0-9,]+)", string: res);
    if (!isnull(vers[1])) {
      version = str_replace(string: vers[1], find: ",", replace: ".");
      concUrl = url;
    }
  }

  set_kb_item(name: "schneider_clearscada/installed", value: TRUE);

  os_register_and_report(os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows",
                         desc: "Schneider Electric ClearSCADA Detection", runs_key: "windows");

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:schneider-electric:clearscada:");
  if (!cpe)
    cpe = "cpe:/a:schneider-electric:clearscada";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Schneider Electric ClearSCADA", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
