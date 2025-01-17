# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112431");
  script_version("2021-06-24T11:00:30+0000");
  script_cve_id("CVE-2018-19296");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-21 18:34:00 +0000 (Fri, 21 May 2021)");
  script_tag(name:"creation_date", value:"2018-11-19 10:01:22 +0100 (Mon, 19 Nov 2018)");
  script_name("PHPMailer < 5.2.27, 6.x < 6.0.6 Object Injection Attack Vulnerability");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_phpmailer_detect.nasl");
  script_mandatory_keys("phpmailer/detected");

  script_xref(name:"URL", value:"https://github.com/PHPMailer/PHPMailer/releases/tag/v5.2.27");
  script_xref(name:"URL", value:"https://github.com/PHPMailer/PHPMailer/releases/tag/v6.0.6");

  script_tag(name:"summary", value:"This host is running PHPMailer and is prone
  to an object injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PHPMailer before 5.2.27 and 6.x before 6.0.6.");

  script_tag(name:"solution", value:"Upgrade to PHPMailer 5.2.27 or 6.0.6 respectively.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

CPE = "cpe:/a:phpmailer_project:phpmailer";

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version  = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"5.2.27" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.2.27", install_url:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"6.0.0", test_version2:"6.0.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.0.6", install_url:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
