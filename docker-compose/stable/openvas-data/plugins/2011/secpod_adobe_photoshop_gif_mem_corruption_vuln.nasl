###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Photoshop '.GIF' File Processing Memory Corruption Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902618");
  script_version("2020-05-13T14:08:32+0000");
  script_tag(name:"last_modification", value:"2020-05-13 14:08:32 +0000 (Wed, 13 May 2020)");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2011-2131");
  script_bugtraq_id(49106);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Photoshop '.GIF' File Processing Memory Corruption Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Ver");

  script_xref(name:"URL", value:"http://securitytracker.com/id/1025910");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-22.html");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code and cause Denial of Service.");

  script_tag(name:"affected", value:"Adobe Photoshop CS5 through CS5.1");

  script_tag(name:"insight", value:"The flaw is caused by memory corruptions error when processing a crafted
  '.GIF' file.");

  script_tag(name:"summary", value:"This host is installed with Adobe Photoshop and is prone to
  remote code execution vulnerability.");

  script_tag(name:"solution", value:"Apply patch APSB11-22 for Adobe Photoshop CS5 and CS5.1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod", value:"30"); # nb: Version check below doesn't check the patch version...

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/a:adobe:photoshop_cs5",
                      "cpe:/a:adobe:photoshop_cs5.1" );

if( ! infos = get_app_version_and_location_from_list( cpe_list:cpe_list, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_equal( version:vers, test_version:"12.0" ) ||
    version_is_equal( version:vers, test_version:"12.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
