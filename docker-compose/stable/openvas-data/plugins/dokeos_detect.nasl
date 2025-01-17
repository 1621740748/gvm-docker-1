###############################################################################
# OpenVAS Vulnerability Test
#
# Dokeos Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100154");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-11-12T10:09:08+0000");
  script_tag(name:"last_modification", value:"2020-11-12 10:09:08 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2009-04-23 21:21:19 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Dokeos Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running Dokeos, an open source online learning suite.");

  script_xref(name:"URL", value:"http://www.dokeos.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/dokeos", http_cgi_dirs( port:port ) ) ) {
 install = dir;
 if( dir == "/" ) dir = "";

 url = dir + "/index.php";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL ) continue;

 if ((egrep(pattern: 'Platform <a [^>]+>Dokeos', string: buf, icase: TRUE) ||
      egrep(pattern: 'id="platformmanager"', string: buf, icase: TRUE) ||
      '<meta name="Generator" content="Dokeos">' >< buf) &&
      egrep(pattern: "Set-Cookie: dk_sid", string: buf)) {
    vers = "unknown";

    version = eregmatch(string: buf, pattern: "(Platform|Portal) <a [^>]+>Dokeos ([0-9.]+)",icase:TRUE);
    if (!isnull(version[2]))
      vers = version[2];
    else {
      version = eregmatch(pattern: ">Dokeos ([0-9.]+)", string: buf);
      if (!isnull(version[1]))
        vers = version[1];
    }

    set_kb_item(name: "dokeos/installed", value: TRUE);

    cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:dokeos:dokeos:");
    if (!cpe)
      cpe = 'cpe:/a:dokeos:dokeos';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Dokeos", version: vers, install: install, cpe: cpe,
                                             concluded: version[0]),
                port: port);
    exit(0);
  }
}

exit(0);
