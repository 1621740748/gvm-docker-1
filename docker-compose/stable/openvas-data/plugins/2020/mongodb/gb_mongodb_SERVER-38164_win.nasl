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

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144964");
  script_version("2021-04-22T08:55:01+0000");
  script_tag(name:"last_modification", value:"2021-04-22 08:55:01 +0000 (Thu, 22 Apr 2021)");
  script_tag(name:"creation_date", value:"2020-12-02 06:52:01 +0000 (Wed, 02 Dec 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2018-20805");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB 3.6 < 3.6.10, 4.0 < 4.0.5 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MongoDB is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A user authorized to perform database queries may trigger denial of service by
  issuing specially crafted queries, which perform an $elemMatch.");

  script_tag(name:"affected", value:"MongoDB versions 3.6 prior to 3.6.10 and 4.0 prior to 4.0.5.");

  script_tag(name:"solution", value:"Update to version 3.6.10, 4.0.5 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-38164");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.6", test_version2: "3.6.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.10");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
