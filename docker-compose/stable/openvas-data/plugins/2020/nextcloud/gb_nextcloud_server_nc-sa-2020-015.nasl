# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.143629");
  script_version("2020-03-27T07:20:35+0000");
  script_tag(name:"last_modification", value:"2020-03-27 07:20:35 +0000 (Fri, 27 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-24 06:36:32 +0000 (Tue, 24 Mar 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2020-8139");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 16.0.9, 17.x < 17.0.4, 18.0.0 Access Control Vulnerability (NC-SA-2020-015)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an information disclosure vulnerability due to a
  missing access control check.");

  script_tag(name:"insight", value:"A missing access control check in Nextcloud Server causes hide-download shares
  to be downloadable when appending /download to the URL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Nextcloud server versions prior 16.0.9, 17.x and 18.x.");

  script_tag(name:"solution", value:"Update to version 16.0.9, 17.0.4, 18.0.1 or later.");

  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2020-015");

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

if (version_is_less(version: version, test_version: "16.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "17.0.0", test_version2: "17.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "18.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
