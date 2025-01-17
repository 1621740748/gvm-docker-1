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
  script_oid("1.3.6.1.4.1.25623.1.0.803317");
  script_version("2021-04-13T14:13:08+0000");
  script_cve_id("CVE-2012-2688");
  script_bugtraq_id(54638);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2013-03-01 12:30:11 +0530 (Fri, 01 Mar 2013)");
  script_name("PHP '_php_stream_scandir()' Buffer Overflow Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/427456.php");
  script_xref(name:"URL", value:"http://secunia.com/advisories/cve_reference/CVE-2012-2688");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  and failed attempts will likely result in denial-of-service conditions.");

  script_tag(name:"affected", value:"PHP version before 5.3.15 and 5.4.x before 5.4.5");

  script_tag(name:"insight", value:"Flaw related to overflow in the _php_stream_scandir function in the
  stream implementation.");

  script_tag(name:"solution", value:"Update to PHP 5.4.5 or 5.3.15 or later.");

  script_tag(name:"summary", value:"PHP is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"5.3.15")||
  version_in_range(version:vers, test_version:"5.4", test_version2: "5.4.4")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.3.15/5.4.5");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
