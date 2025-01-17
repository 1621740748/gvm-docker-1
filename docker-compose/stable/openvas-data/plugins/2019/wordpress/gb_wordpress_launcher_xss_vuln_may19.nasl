# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113393");
  script_version("2020-08-06T13:39:56+0000");
  script_tag(name:"last_modification", value:"2020-08-06 13:39:56 +0000 (Thu, 06 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-05-20 10:36:33 +0200 (Mon, 20 May 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-7411");

  script_name("WordPress MyThemeShop Launcher Plugin < 1.0.11 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/launcher/detected");

  script_tag(name:"summary", value:"The MyThemeShop Launcher plugin for WordPress is prone to
  a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple stored cross-site scripting vulnerabilities allow remote
  authenticated users to inject arbitrary web script or HTML via following fields:

  - Title

  - Favicon

  - Meta Description

  - Subscribe Form (Name field label, Last name field label, Email field label)

  - Contact Form (Name field label, Email field label)

  - Social Links (Facebook Page URL, Twitter Page URL, Instagram Page URL, YouTube Page URL,
    LinkedIn Page URL, Google+ Page URL, RSS URL)");

  script_tag(name:"affected", value:"WordPress MyThemeShop Launcher plugin through version 1.0.10.");

  script_tag(name:"solution", value:"Update to version 1.0.11 or later.");

  script_xref(name:"URL", value:"https://metamorfosec.com/Files/Advisories/METS-2019-002-Multiple_Stored_XSS_Vulnerabilities_in_the_MyThemeShop_Launcher_plugin_v1.0.8_for_WordPress.txt");

  exit(0);
}

CPE = "cpe:/a:mythemeshop:launcher";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.0.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
