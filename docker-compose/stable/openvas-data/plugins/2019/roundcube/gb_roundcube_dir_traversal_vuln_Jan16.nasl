# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:roundcube:webmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114127");
  script_version("2020-12-08T08:52:45+0000");
  script_tag(name:"last_modification", value:"2020-12-08 08:52:45 +0000 (Tue, 08 Dec 2020)");
  script_tag(name:"creation_date", value:"2019-09-03 14:56:41 +0200 (Tue, 03 Sep 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2015-8794");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Roundcube Webmail < 1.0.6 And 1.1.x < 1.1.2 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_detect.nasl");
  script_mandatory_keys("roundcube/detected");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to a directory traversal vulnerability.");

  script_tag(name:"insight", value:"This absolute path traversal vulnerability in program/steps/addressbook/photo.inc
  allows remote authenticated users to read arbitrary files via a full pathname in the _alt parameter,
  related to contact photo handling.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Roundcube Webmail versions before 1.0.6 and 1.1.x before 1.1.2.");

  script_tag(name:"solution", value:"Update to version 1.1.2, or later.");

  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/issues/4817");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version_is_less(version: version, test_version: "1.0.6") ||
   version_is_less_equal(version: version, test_version: "1.1") ||
   version_in_range(version: version, test_version: "1.1beta", test_version2: "1.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.2", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
