# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.805656");
  script_version("2021-04-13T14:13:08+0000");
  script_cve_id("CVE-2015-3329", "CVE-2015-3307", "CVE-2015-2783", "CVE-2015-1352",
                "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4602", "CVE-2015-4603",
                "CVE-2015-4604", "CVE-2015-4605", "CVE-2015-3411", "CVE-2015-3412");
  script_bugtraq_id(74240, 74239, 74703, 75251, 75252, 74413, 75249, 75241, 75233,
                    75255, 75250);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2015-06-17 16:00:15 +0530 (Wed, 17 Jun 2015)");
  script_name("PHP Multiple Vulnerabilities - 03 - Jun15 (Windows)");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple stack-based buffer overflows in the 'phar_set_inode' function in
    phar_internal.h script in PHP.

  - Vulnerabilities in 'phar_parse_metadata' and 'phar_parse_pharfile' functions
    in ext/phar/phar.c script in PHP.

  - A NULL pointer dereference flaw in the 'build_tablename' function in
  'ext/pgsql/pgsql.c' script that is triggered when handling NULL return values
  for 'token'");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service, to obtain sensitive
  information from process memory and to execute arbitrary code via crafted
  dimensions.");

  script_tag(name:"affected", value:"PHP versions before 5.4.40, 5.5.x before
  5.5.24, and 5.6.x before 5.6.8");

  script_tag(name:"solution", value:"Update to PHP 5.4.40 or 5.5.24 or 5.6.8
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=69085");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/06/01/4");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^5\.5")
{
  if(version_in_range(version:vers, test_version:"5.5.0", test_version2:"5.5.23"))
  {
    fix = "5.5.24";
    VULN = TRUE;
  }
}

if(vers =~ "^5\.6")
{
  if(version_in_range(version:vers, test_version:"5.6.0", test_version2:"5.6.7"))
  {
    fix = "5.6.8";
    VULN = TRUE;
  }
}

if(vers =~ "^5\.4")
{
  if(version_is_less(version:vers, test_version:"5.4.40"))
  {
    fix = "5.4.40";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = 'Installed Version: ' + vers + '\n' +
           'Fixed Version:     ' + fix + '\n';
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
