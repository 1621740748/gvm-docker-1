###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco FireSIGHT Detection (HTTP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106160");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-07-29 14:46:43 +0700 (Fri, 29 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco FireSIGHT Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Cisco FireSIGHT Management
Center");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/products/security/firesight-management-center/index.html");


  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:443);

res = http_get_cache(item: "/login.cgi", port: port);

if ("<b>Sourcefire Support</b>" >< res && "<b>Cisco Support</b>" >< res) {
  version = "unknown";
  build = "unknown";

  vers_build = eregmatch(string: res, pattern: "login.css\?v=([0-9.-]+)");
  if (!isnull(vers_build[1])) {
    tmp = split(vers_build[1], sep: "-", keep: FALSE);
    if (!isnull(tmp[0]))
      version = tmp[0];
    if (!isnull(tmp[1]))
      build = tmp[1];
  }
  else
    exit(0);

  if (version != "unknown")
    set_kb_item(name: "cisco_firesight_management_center/version", value: version);

  if (build != "unknown")
    set_kb_item(name: "cisco_firesight_management_center/build", value: build);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:cisco:firesight_management_center:");
  if (!cpe)
    cpe = "cpe:/a:cisco:firesight_management_center";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Cisco FireSIGHT Management Center", version: version,
                                           install: "/", cpe: cpe, concluded: vers_build[0]),
              port: port);

  exit(0);
}

exit(0);
