###############################################################################
# OpenVAS Vulnerability Test
#
# CMS Made Simple Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100497");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-02-17 20:53:20 +0100 (Wed, 17 Feb 2010)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("CMS Made Simple Detection");

  script_tag(name:"summary", value:"Detection of CMS Made Simple

This script sends an HTTP GET request and tries to get the version from the response.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.cmsmadesimple.org/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

http_port = http_get_port(default:80);

if(!http_can_host_php(port:http_port))
  exit(0);

foreach dir (make_list_unique("/cms", "/cmsmadesimple", http_cgi_dirs(port: http_port))){
  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:http_port );

  if (egrep(pattern: 'meta name="Generator" content="CMS Made Simple', string: buf, icase: TRUE)) {
    vers = "unknown";

    version = eregmatch(string: buf, pattern: "version ([0-9.]+)",icase:TRUE);

    if (!isnull(version[1])) {
       vers=version[1];
    }
    else {
      url = dir + "/doc/CHANGELOG.txt";
      req = http_get(port: http_port, item: url);
      res = http_keepalive_send_recv(port: http_port, data: req);

      version = eregmatch(pattern: "Version ([0-9.]+)", string: res);
      if (!isnull(version[1])) {
        vers = version[1];
        concUrl = url;
      }
    }

    set_kb_item(name:"cmsmadesimple/installed",value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:cmsmadesimple:cms_made_simple:");
    if (!cpe)
      cpe = "cpe:/a:cmsmadesimple:cms_made_simple";

    register_product(cpe:cpe, location:install, port:http_port, service:"www");

    log_message(data: build_detection_report(app: "CMSMadeSimple", version: vers, install: install,
                                             cpe: cpe, concluded: version[0], concludedUrl: concUrl),
                port:http_port);
    exit(0);
  }
}

exit(0);
