# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:liferay:liferay_portal";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144612");
  script_version("2021-07-13T02:01:14+0000");
  script_tag(name:"last_modification", value:"2021-07-13 02:01:14 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-09-23 05:31:01 +0000 (Wed, 23 Sep 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-30 15:29:00 +0000 (Wed, 30 Sep 2020)");

  script_cve_id("CVE-2020-15839");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Liferay Portal < 7.3.3 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_liferay_detect.nasl");
  script_mandatory_keys("liferay/detected");

  script_tag(name:"summary", value:"Liferay Portal is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Liferay Portal does not restrict the size of 'multipart/form-data' encoded
  form post, which allows remote authenticated users to conduct denial-of-service attacks by uploading large files(s).");

  script_tag(name:"affected", value:"Liferay Portal version 7.3.2 and prior.");

  script_tag(name:"solution", value:"Update to version 7.3.3 or later.");

  script_xref(name:"URL", value:"https://portal.liferay.dev/learn/security/known-vulnerabilities/-/asset_publisher/HbL5mxmVrnXW/content/id/119784928");

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

if (version_is_less(version: version, test_version: "7.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
