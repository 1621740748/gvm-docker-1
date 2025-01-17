###############################################################################
# OpenVAS Vulnerability Test
#
# F-Secure Internet Gatekeeper Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103081");
  script_version("2021-05-14T13:11:51+0000");
  script_tag(name:"last_modification", value:"2021-05-14 13:11:51 +0000 (Fri, 14 May 2021)");
  script_tag(name:"creation_date", value:"2011-02-21 13:57:38 +0100 (Mon, 21 Feb 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("F-Secure Internet Gatekeeper Detection (HTTP)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9012);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of F-Secure Internet Gatekeeper.");

  script_xref(name:"URL", value:"https://www.f-secure.com/en/business/downloads/internet-gatekeeper");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 9012);

url = "/";
buf = http_get_cache(port: port, item: url);
if("<TITLE>F-Secure Internet Gatekeeper</TITLE>" >!< buf && "fswebui.css" >!< buf) {
  url = "/login.jsf";
  buf = http_get_cache(item: url, port: port);

  if("<title>F-Secure Anti-Virus Gateway for Linux</title>" >!< buf)
    exit(0);
}

# nb: Version seems to be available only after a login.
vers = "unknown";
install = "/";

set_kb_item(name: "fsecure/internet_gatekeeper/detected", value: TRUE);

# Runs only on Linux based OS, appliance is running on CentOS
os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", port:port, desc:"F-Secure Internet Gatekeeper Detection (HTTP)", runs_key:"unixoide" );

cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:f-secure:internet_gatekeeper:");
if (!cpe)
  cpe = "cpe:/a:f-secure:internet_gatekeeper";

register_product(cpe: cpe, location: install, port: port, service: "www");

log_message(data: build_detection_report(app: "F-Secure Internet Gatekeeper", version: vers, install: install,
                                         cpe: cpe, concludedUrl: url),
            port: port);

exit(0);
