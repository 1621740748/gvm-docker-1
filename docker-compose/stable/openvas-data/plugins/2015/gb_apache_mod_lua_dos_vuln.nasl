# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805637");
  script_version("2021-03-01T08:21:56+0000");
  script_cve_id("CVE-2014-8109");
  script_bugtraq_id(73040);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-03-01 08:21:56 +0000 (Mon, 01 Mar 2021)");
  script_tag(name:"creation_date", value:"2015-05-27 12:15:46 +0530 (Wed, 27 May 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Only vulnerable if mod_lua is enabled
  script_name("Apache HTTP Server 'mod_lua' Denial of Service Vulnerability May15");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to a vulnerability in
  LuaAuthzProvider that is triggered if a user-supplied LUA script is supplied
  more than once with different arguments.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to bypass intended access restrictions in opportunistic
  circumstances by leveraging multiple Require directives.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.3.x through
  2.4.10.");

  script_tag(name:"solution", value:"Update to version 2.4.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  script_xref(name:"URL", value:"http://www.rapid7.com/db/vulnerabilities/apache-httpd-cve-2014-8109");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_mandatory_keys("apache/http_server/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"2.3.0", test_version2:"2.4.10")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.12", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);