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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144898");
  script_version("2021-07-08T10:18:29+0000");
  script_tag(name:"last_modification", value:"2021-07-08 10:18:29 +0000 (Thu, 08 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-11-06 03:28:37 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-13 16:38:00 +0000 (Fri, 13 Nov 2020)");

  script_cve_id("CVE-2020-22278");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("phpMyAdmin <= 5.0.2 CSV Injection Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a CSV injection vulnerability via Export
  Section.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"phpMyAdmin version 5.0.2 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 08th July, 2021.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://cert.ikiu.ac.ir/public-files/news/document/CVE-99/CVE-2020-22278.pdf");

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

if (version_is_less_equal(version: version, test_version: "5.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);