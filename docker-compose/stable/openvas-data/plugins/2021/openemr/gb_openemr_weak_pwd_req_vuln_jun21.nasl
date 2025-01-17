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

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112908");
  script_version("2021-07-05T08:33:28+0000");
  script_tag(name:"last_modification", value:"2021-07-05 08:33:28 +0000 (Mon, 05 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-06-25 08:49:11 +0000 (Fri, 25 Jun 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-25923");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR 5.0.0 < 6.0.0.2 Weak Password Requirement Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_mandatory_keys("openemr/installed");

  script_tag(name:"summary", value:"OpenEMR is prone to a weak password requirement vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The application does not enforce a maximum password length limit
  during the user creation mechanism. The vulnerability can be reproduced assuming the malicious user is
  aware of the first 72 characters of the victim user's password.");

  script_tag(name:"impact", value:"Successful exploitation may lead to a complete account takeover.");

  script_tag(name:"affected", value:"OpenEMR version 5.0.0 through 6.0.0.1.");

  script_tag(name:"solution", value:"Update to version 6.0.0.2 or later.");

  script_xref(name:"URL", value:"https://www.whitesourcesoftware.com/vulnerability-database/CVE-2021-25923");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "6.0.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
