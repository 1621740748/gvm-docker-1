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

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117284");
  script_version("2021-04-06T09:40:08+0000");
  script_tag(name:"last_modification", value:"2021-04-06 09:40:08 +0000 (Tue, 06 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-06 09:23:37 +0000 (Tue, 06 Apr 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2021-21252");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS 6.0.x < 7.0.25, 8.0.x < 8.0.12 ReDoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to a regular expression denial of
  service (ReDoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"Thirdparty library jquery-validate is vulnerable to a
  ReDoS via the url method.");

  script_tag(name:"affected", value:"OTRS 6.0.x, 7.0.x and 8.0.x.");

  script_tag(name:"solution", value:"Update to version 7.0.25, 8.0.12 or later.");

  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2021-06/");

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

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "7.0.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
