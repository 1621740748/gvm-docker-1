# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146278");
  script_version("2021-07-26T07:53:29+0000");
  script_tag(name:"last_modification", value:"2021-07-26 07:53:29 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-14 08:45:46 +0000 (Wed, 14 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-22918", "CVE-2021-22921");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 12.x < 12.22.2, 14.x < 14.17.2, 16.x < 16.4.1 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nodejs_detect_win.nasl");
  script_mandatory_keys("Nodejs/Win/Ver");

  script_tag(name:"summary", value:"Node.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-22918: Out of bounds read in libuv

  - CVE-2021-22921: Node installer local privilege escalation");

  script_tag(name:"affected", value:"Node.js 12.x through 12.22.1, 14.x through 14.17.1 and 16.x
  through 16.4.0.");

  script_tag(name:"solution", value:"Update to version 12.22.2, 14.17.2, 16.4.1 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/july-2021-security-releases/");

  exit(0);

}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.22.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.22.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "14.0", test_version2: "14.17.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.17.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "16.0", test_version2: "16.04.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.04.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
