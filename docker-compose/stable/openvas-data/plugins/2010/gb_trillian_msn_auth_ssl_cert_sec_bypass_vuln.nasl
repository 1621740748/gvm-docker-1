###############################################################################
# OpenVAS Vulnerability Test
#
# Trillian MSN SSL Certificate Validation Security Bypass Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800177");
  script_version("2020-04-23T12:22:09+0000");
  script_tag(name:"last_modification", value:"2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)");
  script_tag(name:"creation_date", value:"2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)");
  script_bugtraq_id(35509);
  script_cve_id("CVE-2009-4831");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("Trillian MSN SSL Certificate Validation Security Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_trillian_detect.nasl");
  script_mandatory_keys("Trillian/Ver");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51400");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform man-in-the-middle
  attacks.");

  script_tag(name:"affected", value:"Cerulean Studios Trillian 3.1 Basic on windows.");

  script_tag(name:"insight", value:"The flaw is due to improper varification of SSL certificate before
  sending MSN user credentials.");

  script_tag(name:"summary", value:"This host is installed with Trillian and is prone to security bypass
  vulnerability.");

  script_tag(name:"solution", value:"Upgrade to Cerulean Studios Trillian version 4.2 or later.");

  script_tag(name:"qod", value:"30"); # nb: The pro version isn't affected, but our detection can't pick up the difference
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:ceruleanstudios:trillian";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "3.1", test_version2: "3.1.14.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2", install_path: location );
  report = report_fixed_ver(installed_version:version, vulnerable_range:"3.1 - 3.1.14.0");
  security_message(port: 0, data: report);
  exit( 0 );
}

exit( 99 );
