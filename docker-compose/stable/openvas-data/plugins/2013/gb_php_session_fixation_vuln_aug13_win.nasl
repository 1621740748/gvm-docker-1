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
  script_oid("1.3.6.1.4.1.25623.1.0.803737");
  script_version("2021-04-13T14:13:08+0000");
  script_cve_id("CVE-2011-4718");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2013-08-19 12:03:50 +0530 (Mon, 19 Aug 2013)");
  script_name("PHP Sessions Subsystem Session Fixation Vulnerability - Aug13 (Windows)");

  script_tag(name:"summary", value:"PHP is prone to a session fixation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to PHP version 5.5.2 or later.");

  script_tag(name:"insight", value:"PHP contains an unspecified flaw in the Sessions subsystem.");

  script_tag(name:"affected", value:"PHP version prior to 5.5.2 on Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to hijack web sessions by
  specifying a session ID.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54562");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2011-4718");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=commit;h=169b78eb79b0e080b67f9798708eb3771c6d0b2f");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=commit;h=25e8fcc88fa20dc9d4c47184471003f436927cde");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

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

if(version_is_less(version:vers, test_version:"5.5.2")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.5.2");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
