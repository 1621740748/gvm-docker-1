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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113724");
  script_version("2021-02-15T14:13:17+0000");
  script_tag(name:"last_modification", value:"2021-02-15 14:13:17 +0000 (Mon, 15 Feb 2021)");
  script_tag(name:"creation_date", value:"2020-07-16 07:51:36 +0000 (Thu, 16 Jul 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-20907");

  script_name("Python <= 3.8.3 DoS Vulnerability (Mac OS X)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl");
  script_mandatory_keys("python/mac-os-x/detected");

  script_tag(name:"summary", value:"Python is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker is able to craft a TAR archive leading to an infinite loop
  when opened by tarfile.open, because _proc_pax lacks header validation.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to deny legitimate users access to the application or exhaust a system's resources.");

  script_tag(name:"affected", value:"Python through version 3.8.3.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_xref(name:"URL", value:"https://bugs.python.org/issue39017");

  exit(0);
}

CPE = "cpe:/a:python:python";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "3.8.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "See references", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
