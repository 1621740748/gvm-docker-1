# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.804849");
  script_version("2021-04-13T14:13:08+0000");
  script_cve_id("CVE-2014-4721");
  script_bugtraq_id(68423);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2014-09-22 09:50:48 +0530 (Mon, 22 Sep 2014)");

  script_name("PHP Information Disclosure Vulnerability - 01 - Sep14");

  script_tag(name:"summary", value:"PHP is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in the
  'hp_print_info' function within /ext/standard/info.c script.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  attacker to gain access to sensitive information.");

  script_tag(name:"affected", value:"PHP before version 5.3.x before 5.3.29,
  5.4.x before 5.4.30, 5.5.x before 5.5.14");

  script_tag(name:"solution", value:"Update to PHP version 5.3.29 or 5.4.30
  or 5.5.14 or later.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67498");
  script_xref(name:"URL", value:"https://www.sektioneins.de/en/blog/14-07-04-phpinfo-infoleak.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(phpVer =~ "^5\.[3-5]"){
  if(version_in_range(version:phpVer, test_version:"5.5.0", test_version2:"5.5.13")||
     version_in_range(version:phpVer, test_version:"5.4.0", test_version2:"5.4.29")||
     version_in_range(version:phpVer, test_version:"5.3.0", test_version2:"5.3.28")){
    report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.29/5.4.30/5.5.14");
    security_message(data:report, port:phpPort);
    exit(0);
  }
}

exit(99);
