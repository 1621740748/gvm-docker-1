# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112676");
  script_version("2019-12-30T15:50:06+0000");
  script_tag(name:"last_modification", value:"2019-12-30 15:50:06 +0000 (Mon, 30 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-18 08:30:11 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-19848", "CVE-2019-19849", "CVE-2019-19850");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 8.x.x <= 8.7.29, 9.x.x <= 9.5.11 and 10.x.x <= 10.2.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Multiple cross-site scripting issues

  - Directory traversal

  - SQL injection

  - Insecure deserialization.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"TYPO3 versions 8.0.0 through 8.7.29, 9.0.0 through 9.5.11 and 10.0.0 through 10.2.0.");

  script_tag(name:"solution", value:"Update to version 8.7.30, 9.5.12 or 10.2.2.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-021/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-022/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-023/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-024/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-025/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-026/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version_in_range(version: version, test_version: "8.0.0", test_version2: "8.7.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.30", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "9.0.0", test_version2: "9.5.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.12", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "10.0.0", test_version2: "10.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.2.2", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
