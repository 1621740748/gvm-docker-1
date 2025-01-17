# Copyright (C) 2008 Greenbone Networks GmbH
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

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800052");
  script_version("2021-02-15T14:13:17+0000");
  script_cve_id("CVE-2008-4864");
  script_bugtraq_id(31976);
  script_tag(name:"last_modification", value:"2021-02-15 14:13:17 +0000 (Mon, 15 Feb 2021)");
  script_tag(name:"creation_date", value:"2008-11-11 09:00:11 +0100 (Tue, 11 Nov 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Python Imageop Module imageop.crop() BOF Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/46606");

  script_tag(name:"impact", value:"Remote exploitation will allow execution of arbitrary
  code via large number of integer values to crop module, which leads to a buffer overflow
  (Segmentation fault).");

  script_tag(name:"affected", value:"Python 1.5.2 to 2.5.1.");

  script_tag(name:"insight", value:"The flaw exists due the way module imageop.crop() handles
  the arguments as input in imageop.c file.");

  script_tag(name:"solution", value:"Update to Python 2.5.2 or later.");

  script_tag(name:"summary", value:"Python is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"1.5.2", test_version2:"2.5.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.5.2", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
