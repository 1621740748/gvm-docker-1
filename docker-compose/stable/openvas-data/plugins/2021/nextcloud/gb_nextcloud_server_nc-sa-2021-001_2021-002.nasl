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

CPE = "cpe:/a:nextcloud:nextcloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145263");
  script_version("2021-02-09T09:45:58+0000");
  script_tag(name:"last_modification", value:"2021-02-09 09:45:58 +0000 (Tue, 09 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-01-28 02:28:44 +0000 (Thu, 28 Jan 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2020-8293", "CVE-2020-8294");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server Multiple Vulnerabilities (NC-SA-2021-001, NC-SA-2021-002)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Potential DDoS when posting long data into workflow validation rules (CVE-2020-8293)

  - Stored XSS in markdown file with Nextcloud Talk using Internet Explorer (CVE-2020-8294)");

  script_tag(name:"affected", value:"Nextcloud server prior to versions 18.0.11, 19.0.5 or 20.0.2.");

  script_tag(name:"solution", value:"Update to version 18.0.11, 19.0.5, 20.0.2 or later.");

  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2021-001");
  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2021-002");

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

if (version_is_less(version: version, test_version: "18.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "19.0", test_version2: "19.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.0.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "20.0", test_version2: "20.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
