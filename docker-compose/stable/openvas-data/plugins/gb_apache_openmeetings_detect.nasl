###############################################################################
# OpenVAS Vulnerability Test
#
# Apache OpenMeetings Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808657");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-08-23 14:59:46 +0530 (Tue, 23 Aug 2016)");
  script_name("Apache OpenMeetings Detection");

  script_tag(name:"summary", value:"Detection of Installed version of Apache OpenMeetings application.

  This script sends HTTP GET requests and tries to confirm the presence of Apache
  OpenMeetings from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 5080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:5080);

foreach dir(make_list_unique("/", "/openmeetings", "/apache/openmeetings", http_cgi_dirs(port:port)))
{
  install = dir;
  if(dir == "/") dir = "";

  req = http_get(item: dir + "/signin", port:port);
  res = http_send_recv(port:port, data:req);

  if('org-apache-openmeetings-web-pages-auth-SignInPage-0' >< res && 'Username or mail address<' >< res && '>Password<' >< res)
  {
    version = "unknown";
    found = FALSE;

    set_kb_item(name:"Apache/Openmeetings/Installed", value:TRUE);

    req = http_get(item: dir + "/services/info/version", port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(ver = eregmatch(pattern:'"version":"(.+)","revision"', string:res)){
      found = TRUE;
      conclUrl = http_report_vuln_url(port:port, url:dir + "/services/info/version", url_only:TRUE);
    }

    if(!found){
      req = http_get(item: dir + "/docs/project-summary.html", port:port);
      res = http_keepalive_send_recv(port:port, data:req);

      if(limit = eregmatch(pattern:"<td>Version</td>(.*)<td>Type</td>", string:res)){
        if(ver = eregmatch(pattern:"<td>(.+)</td>", string:limit[1])){
          found = TRUE;
          conclUrl = http_report_vuln_url(port:port, url:dir + "/docs/project-summary.html", url_only:TRUE);
        }
      }
    }

    if(found){
      version = ver[1];
      set_kb_item(name:"Apache/Openmeetings/version", value:version);
    }

    cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:apache:openmeetings:");
    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data:build_detection_report(app:"Apache OpenMeetings",
                                             version:version,
                                             install:install,
                                             cpe:cpe,
                                             concluded:ver[0],
                                             concludedUrl:conclUrl),
                                             port:port);
    exit(0);
  }
}
exit(0);
