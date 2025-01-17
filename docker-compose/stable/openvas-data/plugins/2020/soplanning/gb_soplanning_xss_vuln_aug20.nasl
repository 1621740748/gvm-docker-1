# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113741");
  script_version("2020-08-18T09:42:52+0000");
  script_tag(name:"last_modification", value:"2020-08-18 09:42:52 +0000 (Tue, 18 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-12 08:47:03 +0000 (Wed, 12 Aug 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-15597");

  script_name("Simple Online Planning <= 1.46.01 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_soplanning_detect.nasl");
  script_mandatory_keys("soplanning/detected");

  script_tag(name:"summary", value:"Simple Online Planning is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is exploitable
  via the Project Name, Statutes Comment, Places Comment, or Resources Comment field.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"Simple Online Planning through version 1.46.01.");

  script_tag(name:"solution", value:"Update to version 1.47 or later.");

  script_xref(name:"URL", value:"https://www.sevenlayers.com/index.php/364-soplanning-v1-46-01-xss-session-hijack");

  exit(0);
}

CPE = "cpe:/a:soplanning:soplanning";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.47" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.47", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );