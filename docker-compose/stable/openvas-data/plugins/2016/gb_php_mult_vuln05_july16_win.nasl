# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.808633");
  script_version("2021-04-13T14:13:08+0000");
  script_cve_id("CVE-2016-6288", "CVE-2016-6289", "CVE-2016-6290", "CVE-2016-6291",
                "CVE-2016-6292", "CVE-2016-6294", "CVE-2016-6295", "CVE-2016-6296",
                "CVE-2016-6297");
  script_bugtraq_id(92111, 92074, 92097, 92073, 92078, 92115, 92094, 92095,
                    92099);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2016-07-29 11:54:44 +0530 (Fri, 29 Jul 2016)");
  script_name("PHP Multiple Vulnerabilities - 05 - Jul16 (Windows)");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An integer overflow in the 'php_stream_zip_opener' function in
    'ext/zip/zip_stream.c' script.

  - An integer signedness error in the 'simplestring_addn' function in
    'simplestring.c' in xmlrpc-epi.

  - The 'ext/snmp/snmp.c' script improperly interacts with the unserialize
    implementation and garbage collection.

  - The 'locale_accept_from_http' function in 'ext/intl/locale/locale_methods.c'
    script does not properly restrict calls to the ICU 'uloc_acceptLanguageFromHTTP'
    function.

  - An error in the 'exif_process_user_comment' function in 'ext/exif/exif.c'
    script.

  - An error in the 'exif_process_IFD_in_MAKERNOTE' function in 'ext/exif/exif.c'
    script.

  - The 'ext/session/session.c' does not properly maintain a certain hash data
    structure.

  - An integer overflow in the 'virtual_file_ex' function in
    'TSRM/tsrm_virtual_cwd.c' script.

  - An error in the 'php_url_parse_ex' function in 'ext/standard/url.c' script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow
  attackers to cause a denial of service obtain sensitive information from process
  memory, or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"PHP versions before 5.5.38, 5.6.x before
  5.6.24, and 7.x before 7.0.9 on Windows");

  script_tag(name:"solution", value:"Update to PHP version 5.5.38, or 5.6.24,
  or 7.0.9, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/07/24/2");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(version_is_less(version:vers, test_version:"5.5.38"))
{
  fix = '5.5.38';
  VULN = TRUE;
}

else if(version_in_range(version:vers, test_version:"5.6", test_version2:"5.6.23"))
{
  fix = "5.6.24";
  VULN = TRUE;
}

else if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.8"))
{
  fix = "7.0.9";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
