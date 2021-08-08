# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813546");
  script_version("2021-07-01T11:00:40+0000");
  script_cve_id("CVE-2018-1060", "CVE-2018-1061");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-07-01 11:00:40 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-15 20:15:00 +0000 (Wed, 15 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-06-26 13:48:30 +0530 (Tue, 26 Jun 2018)");
  script_name("Python Multiple Denial of Service Vulnerabilities June18 (Windows)");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://bugs.python.org/issue32981");

  script_tag(name:"summary", value:"Python is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to Python:

  - failing to sanitize against backtracking in pop3lib's apop method

  - failing to sanitize against backtracking in 'difflib.IS_LINE_JUNK' method");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to conduct
  a denial of service attack on the affected user.");

  script_tag(name:"affected", value:"Python before versions 2.7.15, 3.4.9, 3.5.6, 3.6.5
  and 3.7.0.beta3.");

  script_tag(name:"solution", value:"Update version 2.7.15, 3.4.9, 3.5.6, 3.6.5
  or 3.7.0.beta3.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"2.7.15")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.7.15", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"3.0", test_version2:"3.4.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.4.9", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"3.5", test_version2:"3.5.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.5.6", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"3.6", test_version2:"3.6.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.6.5", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
