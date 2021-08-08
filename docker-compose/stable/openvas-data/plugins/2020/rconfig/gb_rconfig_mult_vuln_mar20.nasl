# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113649");
  script_version("2021-07-07T02:00:46+0000");
  script_tag(name:"last_modification", value:"2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-03-10 10:14:38 +0000 (Tue, 10 Mar 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-12 22:15:00 +0000 (Thu, 12 Mar 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-10220", "CVE-2020-10221", "CVE-2020-13778");

  script_name("rConfig < 3.9.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_rconfig_detect.nasl");
  script_mandatory_keys("rconfig/detected");

  script_tag(name:"summary", value:"rConfig is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The web interface is prone to an SQL injection via
    the searchColumn parameter of the commands.inc.php page.

  - lib/ajaxHandlers/ajaxAddTemplate.php allows remote attackers
    to execute arbitrary OS commands via shell metacharacters
    in the fileName POST parameter.

  - lib/ajaxHandlers/ajaxAddTemplate.php and lib/ajaxHandlers/ajaxEditTemplate.php
    allow remote authenticated attackers to execute arbitrary code on the target machine.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  gain complete control over the target system.");

  script_tag(name:"affected", value:"rConfig through version 3.9.4.");

  script_tag(name:"solution", value:"Update to version 3.9.5 or later.");

  script_xref(name:"URL", value:"https://github.com/v1k1ngfr/exploits-rconfig/blob/master/rconfig_sqli.py");
  script_xref(name:"URL", value:"https://engindemirbilek.github.io/rconfig-3.93-rce");
  script_xref(name:"URL", value:"https://github.com/theguly/exploits/blob/master/CVE-2020-13778.py");

  exit(0);
}

CPE = "cpe:/a:rconfig:rconfig";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "3.9.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.5", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
