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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800110");
  script_version("2021-04-13T14:13:08+0000");
  script_tag(name:"last_modification", value:"2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2008-10-07 16:11:33 +0200 (Tue, 07 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(29009, 27413, 27786);
  script_cve_id("CVE-2008-2050", "CVE-2008-2051", "CVE-2007-4850", "CVE-2008-0599", "CVE-2008-0674");
  script_xref(name:"CB-A", value:"08-0118");
  script_name("PHP Multiple Vulnerabilities - Aug08");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_xref(name:"URL", value:"http://pcre.org/changelog.txt");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://wiki.rpath.com/wiki/Advisories:rPSA-2008-0176");
  script_xref(name:"URL", value:"http://wiki.rpath.com/wiki/Advisories:rPSA-2008-0178");
  script_xref(name:"URL", value:"http://wiki.rpath.com/wiki/Advisories:rPSA-2008-0086");

  script_tag(name:"impact", value:"Successful exploitation could result in remote arbitrary code execution,
  security restrictions bypass, access to restricted files, denial of service.");

  script_tag(name:"affected", value:"PHP version prior to 5.2.6");

  script_tag(name:"insight", value:"The flaws are caused by,

  - an unspecified stack overflow error in FastCGI SAPI (fastcgi.c).

  - an error during path translation in cgi_main.c.

  - an error with an unknown impact/attack vectors.

  - an unspecified error within the processing of incomplete multibyte
  characters in escapeshellcmd() API function.

  - error in curl/interface.c in the cURL library(libcurl), which could be
  exploited by attackers to bypass safe_mode security restrictions.

  - an error in PCRE. i.e buffer overflow error when handling a character class
  containing a very large number of characters with codepoints greater than
  255(UTF-8 mode).");

  script_tag(name:"solution", value:"Update to PHP version 5.2.6 or later.");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) )
  exit( 0 );

if( version_is_less_equal( version:phpVer, test_version:"5.2.5" ) ) {
  report = report_fixed_ver( installed_version:phpVer, fixed_version:"5.2.6" );
  security_message( data:report, port:phpPort );
  exit( 0 );
}

exit( 99 );