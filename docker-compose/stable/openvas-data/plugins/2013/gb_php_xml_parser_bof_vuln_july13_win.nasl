# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803729");
  script_version("2021-04-13T14:13:08+0000");
  script_cve_id("CVE-2013-4113");
  script_bugtraq_id(61128);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2013-07-30 12:28:05 +0530 (Tue, 30 Jul 2013)");
  script_name("PHP XML Handling Heap Buffer Overflow Vulnerability - Jul13 (Windows)");

  script_tag(name:"summary", value:"PHP is prone to a heap based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to PHP version 5.3.27 or later.");

  script_tag(name:"insight", value:"The flaw is triggered as user-supplied input is not properly validated when
  handling malformed XML input.");

  script_tag(name:"affected", value:"PHP version prior to 5.3.27");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a heap-based buffer
  overflow, resulting in a denial of service or potentially allowing the
  execution of arbitrary code.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=65236");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q3/88");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Jul/106");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(phpVer =~ "^5\.3"){
  if(version_in_range(version:phpVer, test_version:"5.3", test_version2: "5.3.26")){
    report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.27");
    security_message(data:report, port:phpPort);
    exit(0);
  }
}

exit(99);
