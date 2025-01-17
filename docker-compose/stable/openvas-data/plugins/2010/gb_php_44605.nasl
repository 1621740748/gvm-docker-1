# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100901");
  script_version("2021-04-13T14:13:08+0000");
  script_tag(name:"last_modification", value:"2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2010-11-10 13:18:12 +0100 (Wed, 10 Nov 2010)");
  script_bugtraq_id(44605);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3870");
  script_name("PHP 'xml_utf8_decode()' UTF-8 Input Validation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44605");
  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=48230");
  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=49687");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc?view=revision&revision=304959");
  script_xref(name:"URL", value:"http://comments.gmane.org/gmane.comp.security.oss.general/3684");
  script_xref(name:"URL", value:"http://www.mandriva.com/en/security/advisories?name=MDVSA-2010:224");

  script_tag(name:"impact", value:"Exploiting this issue can allow attackers to provide unexpected input
  and possibly bypass input-validation protection mechanisms. This can
  aid in further attacks that may utilize crafted user-supplied input.");

  script_tag(name:"affected", value:"Versions prior to PHP 5.3.4 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"PHP is prone to a vulnerability because it fails to
  sufficiently sanitize user-supplied input.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"5", test_version2:"5.3.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.3.4" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
