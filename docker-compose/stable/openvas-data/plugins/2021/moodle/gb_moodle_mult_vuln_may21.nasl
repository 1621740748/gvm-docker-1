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

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146223");
  script_version("2021-07-06T04:35:09+0000");
  script_tag(name:"last_modification", value:"2021-07-06 04:35:09 +0000 (Tue, 06 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-06 04:17:15 +0000 (Tue, 06 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2021-32473", "CVE-2021-32474", "CVE-2021-32475", "CVE-2021-32476");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 3.5.18, 3.8.x < 3.8.9, 3.9.x < 3.9.7, 3.10.x < 3.10.4 Multiple Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-32473: Quiz unreleased grade disclosure via web service

  - CVE-2021-32474: Blind SQL injection possible via MNet authentication

  - CVE-2021-32475: Stored XSS in quiz grading report via user ID number

  - CVE-2021-32476: Files API should mitigate denial-of-service risk when adding to the draft file
  area");

  script_tag(name:"affected", value:"Moodle version 3.5.17 and prior, 3.8 through 3.8.8, 3.9 through
  3.9.6 and 3.10 through 3.10.3.");

  script_tag(name:"solution", value:"Update to version 3.5.18, 3.8.9, 3.9.7, 3.10.4 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=422307");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=422308");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=422309");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=422310");

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

if (version_is_less(version: version, test_version: "3.5.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.8.0", test_version2: "3.8.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.9.0", test_version2: "3.9.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.10.0", test_version2: "3.10.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
