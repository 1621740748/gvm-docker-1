# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146028");
  script_version("2021-06-14T07:12:08+0000");
  script_tag(name:"last_modification", value:"2021-06-14 07:12:08 +0000 (Mon, 14 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-05-28 03:42:00 +0000 (Fri, 28 May 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2021-28652");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid 1.0 < 4.14, 5.0 < 5.0.5 DoS Vulnerability (SQUID-2021:3)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_squid_detect.nasl");
  script_mandatory_keys("squid_proxy_server/installed");

  script_tag(name:"summary", value:"Squid is prone to a denial of service (DoS) vulnerability in
  the Cache Manager.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to an incorrect parser validation bug Squid is vulnerable to
  a DoS attack against the Cache Manager API.

  This problem allows a trusted client to trigger memory leaks which over time lead to a DoS against
  Squid and the machine it is operating on.

  This attack is limited to clients with Cache Manager API access privilege.");

  script_tag(name:"affected", value:"Squid version 1.0 through 4.14 and 5.0 through 5.0.5.");

  script_tag(name:"solution", value:"Update to version 4.15, 5.0.6 or later. See the referenced vendor
  advisory for a workaround.");

  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-m47m-9hvw-7447");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "1.0", test_version2: "4.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
