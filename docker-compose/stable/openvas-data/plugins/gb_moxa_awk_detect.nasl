###############################################################################
# OpenVAS Vulnerability Test
#
# Moxa AWK Series Devices Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.106740");
  script_version("2020-02-03T13:52:45+0000");
  script_tag(name:"last_modification", value:"2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)");
  script_tag(name:"creation_date", value:"2017-04-11 13:52:39 +0200 (Tue, 11 Apr 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa AWK Series Devices Detection");

  script_tag(name:"summary", value:"Detection of Moxa AWK Series Devices (Industrial Wireless LAN Solutions).

  The script sends a connection request to the server and attempts to detect Moxa AWK Series Devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_goahead_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("embedthis/goahead/detected");

  script_xref(name:"URL", value:"http://www.moxa.com/product/Industrial_Wireless_LAN.htm");

  exit(0);
}

CPE = "cpe:/a:embedthis:goahead";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

res = http_get_cache(port: port, item: "/Login.asp");

if ("<title>Moxa AWK-" >< res && "Password508=" >< res && "llogin.gif" >< res) {
  version = "unknown";

  mod = eregmatch(pattern: "Moxa (AWK-[^ ]+)", string: res);
  if (isnull(mod[1]))
    exit(0);

  model = mod[1];

  set_kb_item(name: "moxa_awk/detected", value: TRUE);
  set_kb_item(name: "moxa_awk/model", value: model);

  cpe = "cpe:/h:moxa:" + tolower(model);

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: 'The remote host is a Moxa ' + model + '\n\nCPE: ' + cpe, port: port);
  exit(0);
}

exit(0);
