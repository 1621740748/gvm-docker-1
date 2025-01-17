###############################################################################
# OpenVAS Vulnerability Test
#
# TerraMaster NAS Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106840");
  script_version("2021-01-12T09:04:49+0000");
  script_tag(name:"last_modification", value:"2021-01-12 09:04:49 +0000 (Tue, 12 Jan 2021)");
  script_tag(name:"creation_date", value:"2017-05-31 11:35:51 +0700 (Wed, 31 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("TerraMaster NAS Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of TerraMaster NAS.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8181);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.terra-master.com/html/en/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8181);

url = "/tos/index.php?user/login";

res = http_get_cache(port: port, item: url);

# 4.1.x versions have "TerraMaster" and "Tos_Check_Box"
# 4.2.x versions might miss "TerraMaster" and/or "Tos_Check_Box" but always have "<title>TOS</title>"
if (("TerraMaster" >!< res || "Tos_Check_Box" >!< res) && "<title>TOS</title>" >!< res) {
  res = http_get_cache(port: port, item: "/");
  if ("<title>TerraMaster" >!< res || 'name="minuser"' >!< res || 'name="dataError"' >!< res)
    exit(0);
}

version = "unknown";

# href="/css/ctools.css?ver=TOS3_S2.0_4.1.06">
vers = eregmatch(pattern: "ver=[^_]+_[^_]+_([0-9.]+)", string: res);
if (isnull(vers[1])) {
  url = "/version";
  res = http_get_cache(port: port, item: url);
  # TOS3_S2.0_4.2.07
  vers = eregmatch(pattern: "[^_]+_[^_]+_([0-9.]+)", string: res);
}

if (!isnull(vers[1])) {
  version = vers[1];
  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

set_kb_item(name: "terramaster_nas/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:noontec:terramaster:");
if (!cpe)
  cpe = "cpe:/a:noontec:terramaster";

register_product(cpe: cpe, location: "/", port: port, service: "www");

log_message(data: build_detection_report(app: "TerraMaster NAS", version: version, install: "/", cpe: cpe,
                                         concluded: vers[0], concludedUrl: concUrl),
            port: port);

exit(0);
