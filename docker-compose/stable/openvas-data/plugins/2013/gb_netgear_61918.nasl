###############################################################################
# OpenVAS Vulnerability Test
#
# Multiple NetGear ProSafe Switches Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103773");
  script_bugtraq_id(61918);
  script_cve_id("CVE-2013-4775", "CVE-2013-4776");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_version("2020-12-07T13:33:44+0000");

  script_name("Multiple NetGear ProSafe Switches Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61918");

  script_tag(name:"last_modification", value:"2020-12-07 13:33:44 +0000 (Mon, 07 Dec 2020)");
  script_tag(name:"creation_date", value:"2013-08-22 12:52:30 +0200 (Thu, 22 Aug 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"An attacker can exploit this issue to download configuration file and
  disclose sensitive information. Information obtained may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Try to read /filesystem/startup-config with a HTTP GET request and check the response.");

  script_tag(name:"insight", value:"The web management application fails to restrict URL access to different
  application areas. Remote, unauthenticated attackers could exploit this issue to download the device's
  startup-config, which contains administrator credentials in encrypted form.");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Multiple NetGear ProSafe switches are prone to an information-
  disclosure vulnerability.");

  script_tag(name:"affected", value:"GS724Tv3 and GS716Tv2 - firmware 5.4.1.13

GS724Tv3 and GS716Tv2 - firmware 5.4.1.10

GS748Tv4              - firmware 5.4.1.14

GS510TP               - firmware 5.4.0.6

GS752TPS and GS728TPS - firmware 5.3.0.17

GS728TS and GS725TS   - firmware 5.3.0.17

GS752TXS and GS728TXS - firmware 6.1.0.12");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
res = http_get_cache(item:"/", port:port);
if(!res || res !~ "<TITLE>NETGEAR")
  exit(0);

url = "/filesystem/startup-config";
if(http_vuln_check(port:port, url:url, pattern:"Current Configuration", extra_check:make_list("System Description","System Software Version","network parms"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
