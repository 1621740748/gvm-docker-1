###############################################################################
# OpenVAS Vulnerability Test
#
# Ruby on Rails 'unicode strings' Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:rubyonrails:rails";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902090");
  script_version("2020-07-14T14:24:25+0000");
  script_tag(name:"last_modification", value:"2020-07-14 14:24:25 +0000 (Tue, 14 Jul 2020)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2009-3009");
  script_bugtraq_id(36278);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Ruby on Rails 'unicode strings' Cross-Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_rails_consolidation.nasl");
  script_mandatory_keys("rails/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53036");
  script_xref(name:"URL", value:"http://secunia.com/advisories/product/25856/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2544");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Sep/1022824.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Ruby on Rails version 2.x before to 2.2.3 and 2.3.x before 2.3.4.");

  script_tag(name:"insight", value:"The flaw is due to error in handling of 'escaping' code for the form
  helpers, which does not properly filter HTML code from user-supplied input
  before displaying the input.");

  script_tag(name:"solution", value:"Upgrade to Ruby on Rails version 2.2.3 or 2.3.4 or later.");

  script_tag(name:"summary", value:"This host is running Ruby on Rails and is prone to cross-site
  scripting vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if(version_in_range( version: version, test_version: "2.0", test_version2: "2.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.3.0", test_version2: "2.3.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version:"2.3.4", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
