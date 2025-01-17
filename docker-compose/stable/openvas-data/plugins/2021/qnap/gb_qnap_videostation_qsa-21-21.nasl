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

CPE = "cpe:/a:qnap:video_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146085");
  script_version("2021-06-15T08:02:31+0000");
  script_tag(name:"last_modification", value:"2021-06-15 08:02:31 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-07 04:54:53 +0000 (Mon, 07 Jun 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2021-28812");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Video Station Command Injection Vulnerability (QSA-21-21)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_videostation_http_detect.nasl");
  script_mandatory_keys("qnap/videostation/detected");

  script_tag(name:"summary", value:"QNAP Video Station is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"If exploited, this vulnerability allows remote attackers to execute
  arbitrary commands.");

  script_tag(name:"affected", value:"QNAP Music Station versions prior to 5.5.4 (QTS 4.5.2).");

  script_tag(name:"solution", value:"Update to version 5.5.4 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-21-21");

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

if (version_in_range(version: version, test_version: "5.4.0", test_version2: "5.5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
