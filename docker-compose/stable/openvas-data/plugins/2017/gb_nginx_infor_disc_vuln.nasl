###############################################################################
# OpenVAS Vulnerability Test
#
# nginx Information Disclosure Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811235");
  script_version("2021-02-01T11:36:44+0000");
  script_cve_id("CVE-2017-7529");
  script_bugtraq_id(99534);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-02-01 11:36:44 +0000 (Mon, 01 Feb 2021)");
  script_tag(name:"creation_date", value:"2017-07-17 13:05:26 +0530 (Mon, 17 Jul 2017)");

  script_name("nginx Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"nginx is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an integer overflow
  error in the nginx range filter module and incorrect processing of ranges.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"nginx versions 0.5.6 through 1.12.0 and 1.13.x before 1.13.3.");

  script_tag(name:"solution", value:"Update to ginx version 1.12.1 or 1.13.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"http://nginx.org/en/security_advisories.html");
  script_xref(name:"URL", value:"http://mailman.nginx.org/pipermail/nginx-announce/2017/000200.html");

  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_nginx_consolidation.nasl");
  script_mandatory_keys("nginx/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location ( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version =~ "^1\.13" && version_is_less( version: version, test_version: "1.13.3" ) )
  fix = "1.13.3";

else if( version =~ "^[01]\." ) {
  if( version_in_range( version: version, test_version:"0.5.6", test_version2:"1.12.0" ) )
    fix = "1.12.1";
}

if( fix ) {
  report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
