# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802566");
  script_version("2021-04-13T14:13:08+0000");
  script_cve_id("CVE-2011-4153", "CVE-2012-0781");
  script_bugtraq_id(51417);
  script_tag(name:"last_modification", value:"2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2012-01-23 11:30:34 +0530 (Mon, 23 Jan 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("PHP Multiple Denial of Service Vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://cxsecurity.com/research/103");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026524");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18370/");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-01/0092.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause
  denial of service conditions.");

  script_tag(name:"affected", value:"PHP Version 5.3.8 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An error in application which makes calls to the 'zend_strndup()' function
   without checking the returned values. A local user can run specially
   crafted PHP code to trigger a null pointer dereference in zend_strndup()
   and cause the target service to crash.

  - An error in 'tidy_diagnose' function, which might allows remote attackers
   to cause a denial of service via crafted input.");

  script_tag(name:"solution", value:"Update to PHP version 5.4.0 or later.");

  script_tag(name:"summary", value:"PHP is prone to multiple denial of service (DoS) vulnerabilities.");

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

if(version_is_equal(version:vers, test_version:"5.3.8")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.4.0");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
