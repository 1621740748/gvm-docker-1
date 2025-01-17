###############################################################################
# OpenVAS Vulnerability Test
#
# XWiki Enterprise Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801840");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-09-14T06:17:58+0000");
  script_tag(name:"last_modification", value:"2020-09-14 06:17:58 +0000 (Mon, 14 Sep 2020)");
  script_tag(name:"creation_date", value:"2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("XWiki Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of XWiki.");

  script_xref(name:"URL", value:"https://www.xwiki.org");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/xwiki/bin/login/XWiki/XWikiLogin");

if ("XWiki.XWikiLogin" >< res && "data-xwiki-wiki" >< res) {
  version = "unknown";
  install = "/xwiki";

  # XWiki Enterprise 7.1.1
  # XWiki Debian 11.8.1
  # XWiki Enterprise Jetty HSQLDB 9.4
  # XWiki 11.10.10
  # XWiki Jetty HSQLDB 12.2
  vers = eregmatch(pattern: '"xwikiplatformversion">.*XWiki[^0-9]+([0-9.]+)', string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "xwiki/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:xwiki:xwiki:");
  if (!cpe)
    cpe = "cpe:/a:xwiki:xwiki";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "XWiki", version: version, install: install, cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
